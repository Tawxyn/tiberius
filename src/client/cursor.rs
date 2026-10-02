//! Client-side TDS cursor API.
//!
//! Cursors let the server incrementally materialize a result set, letting the
//! client page through it without buffering the whole thing. Use
//! [`Client::open_cursor`](crate::Client::open_cursor) to start a cursor,
//! [`Cursor::fetch`] to page through rows, and [`Cursor::close`] when done.
//!
//! Dropping a [`Cursor`] without calling [`Cursor::close`] leaks the handle
//! until the connection closes; a warning is emitted via `tracing`.

use std::borrow::Cow;
use std::sync::Arc;

use enumflags2::{bitflags, BitFlags};
use futures_util::io::{AsyncRead, AsyncWrite};
use tracing::{event, Level};

use crate::client::rpc_response::{
    collect_metadata_only_rpc, collect_rpc_batch_results, collect_rpc_outputs, BufferedResultSet,
    OutputValue,
};
use crate::tds::codec::{ColumnData, RpcParam, RpcProcId, RpcProcIdValue, RpcStatus, TokenInfo};
use crate::tds::stream::{QueryStream, TokenStream};
use crate::{Client, Column, PreparedHandle, Row, ToSql};

/// Scroll options for `sp_cursoropen` / `sp_cursorprepexec` (TDS §2.2.6.7).
///
/// These are bitflags — values may be `OR`'d together (e.g. `Fast |
/// ForwardOnly`). Use [`BitFlags`] from `enumflags2` to combine them.
#[bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorScrollOptions {
    /// Keyset-driven cursor.
    Keyset = 0x0001,
    /// Dynamic cursor — rows refresh on each fetch.
    Dynamic = 0x0002,
    /// Forward-only cursor — most efficient for linear scans.
    ForwardOnly = 0x0004,
    /// Static (snapshot) cursor.
    Static = 0x0008,
    /// Keyset cursor with parameterized open.
    Fast = 0x0010,
    /// Statement has bound parameters.
    ParameterizedStmt = 0x1000,
    /// Server-pregenerated parameterized auto-open.
    AutoFetch = 0x2000,
    /// Client caches results (advisory — negotiated).
    AutoClose = 0x4000,
    /// Client-side check for missing rows.
    CheckAcceptedTypes = 0x8000,
    /// Server-side mass-update hint.
    KeysetDrivenPlusParams = 0x0800,
}

/// Concurrency options for `sp_cursoropen` (TDS §2.2.6.7).
///
/// Bitflags — values may be `OR`'d together.
#[bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorConcurrencyOptions {
    /// Read-only cursor.
    ReadOnly = 0x0001,
    /// Scroll locks.
    ScrollLocks = 0x0002,
    /// Optimistic concurrency with values.
    OptimisticCc = 0x0004,
    /// Optimistic concurrency with row versions.
    OptimisticCcVal = 0x0008,
    /// Allow_direct — advanced; server-selected for read-only cursors.
    AllowDirect = 0x2000,
    /// Update in place.
    UpdateInPlace = 0x4000,
}

fn flags_to_i32(bits: u32) -> i32 {
    bits as i32
}

fn i32_to_scroll_flags(v: i32) -> BitFlags<CursorScrollOptions> {
    BitFlags::<CursorScrollOptions>::from_bits_truncate(v as u32)
}

fn i32_to_cc_flags(v: i32) -> BitFlags<CursorConcurrencyOptions> {
    BitFlags::<CursorConcurrencyOptions>::from_bits_truncate(v as u32)
}

/// A cursor fetch direction + row count request.
///
/// Each variant encodes exactly the arguments that are meaningful for that
/// fetch direction, so you can't accidentally pass a `row_num` to `Next` or
/// forget it for `Absolute`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    /// Reposition to the first row and return up to `count` rows.
    First {
        /// Number of rows to return.
        count: i32,
    },
    /// Advance past the current position and return up to `count` rows.
    Next {
        /// Number of rows to return.
        count: i32,
    },
    /// Back up before the current position and return up to `count` rows.
    Prev {
        /// Number of rows to return.
        count: i32,
    },
    /// Reposition to the last row and return up to `count` rows.
    Last {
        /// Number of rows to return.
        count: i32,
    },
    /// Reposition to the 1-based absolute row number `row` and return up to
    /// `count` rows.
    Absolute {
        /// 1-based row position.
        row: i32,
        /// Number of rows to return.
        count: i32,
    },
    /// Reposition by `offset` rows relative to the current position (may be
    /// negative) and return up to `count` rows.
    Relative {
        /// Signed row offset from the current position.
        offset: i32,
        /// Number of rows to return.
        count: i32,
    },
    /// Re-read the current rows without changing position.
    Refresh {
        /// Number of rows to refresh.
        count: i32,
    },
}

impl Fetch {
    /// Encode this request as `(fetch_type_bits, row_num, count)` per TDS
    /// §2.2.6.7. For directions that don't use `row_num`, `0` is sent.
    pub fn encode(self) -> (i32, i32, i32) {
        match self {
            Fetch::First { count } => (0x0001, 0, count),
            Fetch::Next { count } => (0x0002, 0, count),
            Fetch::Prev { count } => (0x0004, 0, count),
            Fetch::Last { count } => (0x0008, 0, count),
            Fetch::Absolute { row, count } => (0x0010, row, count),
            Fetch::Relative { offset, count } => (0x0020, offset, count),
            Fetch::Refresh { count } => (0x0080, 0, count),
        }
    }
}

/// Options controlling a newly opened cursor.
///
/// Use [`CursorOpenOptions::new`] to construct, or reach for
/// [`CursorOpenOptions::forward_only_read_only`] for the cheapest sensible
/// default.
#[derive(Debug, Clone, Copy)]
pub struct CursorOpenOptions {
    scroll: BitFlags<CursorScrollOptions>,
    concurrency: BitFlags<CursorConcurrencyOptions>,
}

impl CursorOpenOptions {
    /// Build options from explicit scroll / concurrency flag sets.
    pub fn new(
        scroll: impl Into<BitFlags<CursorScrollOptions>>,
        concurrency: impl Into<BitFlags<CursorConcurrencyOptions>>,
    ) -> Self {
        Self {
            scroll: scroll.into(),
            concurrency: concurrency.into(),
        }
    }

    /// A fast forward-only, read-only cursor — the cheapest option.
    pub fn forward_only_read_only() -> Self {
        Self {
            scroll: CursorScrollOptions::ForwardOnly.into(),
            concurrency: CursorConcurrencyOptions::ReadOnly.into(),
        }
    }

    /// Requested scroll flags (sent to the server; may be negotiated).
    pub fn scroll(&self) -> BitFlags<CursorScrollOptions> {
        self.scroll
    }

    /// Requested concurrency flags (sent to the server; may be negotiated).
    pub fn concurrency(&self) -> BitFlags<CursorConcurrencyOptions> {
        self.concurrency
    }
}

impl Default for CursorOpenOptions {
    fn default() -> Self {
        Self::forward_only_read_only()
    }
}

/// An opaque handle identifying a cursor on the server.
///
/// Wraps the raw `i32` that TDS ships on the wire so the value can't be
/// confused with other handle-shaped integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CursorHandle(i32);

impl CursorHandle {
    /// Raw wire value. Mainly useful for logging; pass the typed
    /// [`CursorHandle`] around instead of the `i32` whenever possible.
    pub fn as_i32(self) -> i32 {
        self.0
    }
}

impl From<CursorHandle> for i32 {
    fn from(h: CursorHandle) -> Self {
        h.0
    }
}

/// A cursor opened by `sp_cursorprepexec` together with its prepared handle.
///
/// The prepared handle and cursor handle are separate server-side resources.
/// Call [`close_and_unprepare`](Self::close_and_unprepare), or close the
/// cursor and unprepare the statement explicitly.
#[derive(Debug)]
pub struct PreparedCursor {
    prepared_handle: PreparedHandle,
    cursor: Option<Cursor>,
    cursor_handle: CursorHandle,
    scrollopt: BitFlags<CursorScrollOptions>,
    ccopt: BitFlags<CursorConcurrencyOptions>,
    row_count: i32,
    metadata: Option<Vec<Column>>,
    released: bool,
}

impl PreparedCursor {
    /// The server-assigned prepared statement handle.
    pub fn prepared_handle(&self) -> PreparedHandle {
        self.prepared_handle
    }

    /// The server-assigned cursor handle.
    pub fn cursor_handle(&self) -> CursorHandle {
        self.cursor_handle
    }

    /// Negotiated scroll flags returned by the server.
    pub fn scroll_options(&self) -> BitFlags<CursorScrollOptions> {
        self.scrollopt
    }

    /// Negotiated concurrency flags returned by the server.
    pub fn concurrency_options(&self) -> BitFlags<CursorConcurrencyOptions> {
        self.ccopt
    }

    /// Server-reported row count, or `-1` if unknown.
    pub fn row_count(&self) -> i32 {
        self.row_count
    }

    /// Fetch rows from the opened cursor.
    pub async fn fetch<'a, S>(
        &self,
        client: &'a mut Client<S>,
        fetch: Fetch,
    ) -> crate::Result<QueryStream<'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let cursor = self.cursor.as_ref().ok_or_else(|| {
            crate::Error::Protocol("prepared cursor: cursor is already closed".into())
        })?;
        cursor.fetch(client, fetch).await
    }

    /// Fetch only result-set metadata for this cursor without consuming rows.
    ///
    /// This probes the server with
    /// `sp_cursorfetch @fetchtype = Next`, `@rownum = 0`, and `@nrows = 0`,
    /// then captures the first non-empty `COLMETADATA`.
    pub async fn fetch_metadata<S>(&self, client: &mut Client<S>) -> crate::Result<Vec<Column>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let cursor = self.cursor.as_ref().ok_or_else(|| {
            crate::Error::Protocol("prepared cursor: cursor is already closed".into())
        })?;

        if let Some(metadata) = &self.metadata {
            return Ok(metadata.clone());
        }

        client.connection.flush_stream().await?;
        let rpc_params = build_cursorfetch_params(cursor.handle, Fetch::Next { count: 0 });
        client.send_rpc(RpcProcId::CursorFetch, rpc_params).await?;
        collect_metadata_only_rpc(&mut client.connection).await
    }

    /// Close the cursor if it is still open.
    ///
    /// This is idempotent at the wrapper level.
    pub async fn close_cursor<S>(&mut self, client: &mut Client<S>) -> crate::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Some(cursor) = self.cursor.take() {
            cursor.close(client).await?;
        }
        Ok(())
    }

    /// Release the prepared handle, closing the cursor first if needed.
    ///
    /// An open cursor is closed in the same request as the unprepare, so the
    /// two cost one round trip. The unprepare is sent even when the close then
    /// fails; a close error is returned in preference to an unprepare error.
    pub async fn unprepare<S>(mut self, client: &mut Client<S>) -> crate::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let unprepare: (RpcProcIdValue<'static>, _) = (
            RpcProcId::CursorUnprepare.into(),
            vec![build_unprepare_param(self.prepared_handle)],
        );
        let Some(mut cursor) = self.cursor.take() else {
            client.send_rpc(unprepare.0, unprepare.1).await?;
            self.released = true;
            collect_rpc_outputs(&mut client.connection).await?;
            return Ok(());
        };
        client
            .send_rpc_batch(vec![
                (RpcProcId::CursorClose.into(), cursor.close_params()),
                unprepare,
            ])
            .await?;
        // As in `Cursor::close`, both handles are gone from the server's
        // perspective once the request is processed.
        cursor.closed = true;
        self.released = true;
        for result in collect_rpc_batch_results(&mut client.connection, 2).await? {
            result?;
        }
        Ok(())
    }

    /// Close the cursor and release the prepared handle.
    pub async fn close_and_unprepare<S>(self, client: &mut Client<S>) -> crate::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.unprepare(client).await
    }
}

impl Drop for PreparedCursor {
    fn drop(&mut self) {
        if !self.released {
            event!(
                Level::WARN,
                prepared_handle = self.prepared_handle.as_i32(),
                cursor_handle = self.cursor_handle.as_i32(),
                "PreparedCursor dropped without unprepare; server-side handle will leak until the connection closes"
            );
        }
    }
}

/// The outcome of [`Client::cursor_prep_exec`](crate::Client::cursor_prep_exec).
///
/// `sp_cursorprepexec` normally opens a server-side cursor, but when the
/// statement is opened read-only with the
/// [`AllowDirect`](CursorConcurrencyOptions::AllowDirect) concurrency option
/// the server may elect the *AllowDirect* fast path: it prepares the statement
/// but skips opening a cursor and instead streams the result sets inline during
/// the RPC response. SQL Server identifies this path with INFO 16954. This enum
/// reports which path the server took.
#[derive(Debug)]
pub enum CursorPrepExecOutcome {
    /// The server opened a cursor. Page through it with [`PreparedCursor::fetch`].
    Cursor(PreparedCursor),
    /// The server executed the statement directly, returning the result sets
    /// inline. The prepared handle still needs releasing — see
    /// [`DirectResults::unprepare`].
    Direct(DirectResults),
}

impl CursorPrepExecOutcome {
    /// The server-assigned prepared statement handle, which is present in both
    /// outcomes.
    pub fn prepared_handle(&self) -> PreparedHandle {
        match self {
            CursorPrepExecOutcome::Cursor(c) => c.prepared_handle(),
            CursorPrepExecOutcome::Direct(d) => d.prepared_handle(),
        }
    }

    /// `true` if the server took the AllowDirect fast path.
    pub fn is_direct(&self) -> bool {
        matches!(self, CursorPrepExecOutcome::Direct(_))
    }

    /// Consume the outcome, returning the [`PreparedCursor`] if the server
    /// opened a cursor.
    ///
    /// An AllowDirect response is returned intact as `Err(DirectResults)` so
    /// its prepared handle and buffered rows remain available for cleanup and
    /// consumption.
    pub fn into_cursor(self) -> std::result::Result<PreparedCursor, DirectResults> {
        match self {
            CursorPrepExecOutcome::Cursor(c) => Ok(c),
            CursorPrepExecOutcome::Direct(d) => Err(d),
        }
    }

    /// Consume the outcome, returning the [`DirectResults`] if the server took
    /// the AllowDirect fast path.
    ///
    /// A normal cursor response is returned intact as `Err(PreparedCursor)` so
    /// both server-side handles remain available for fetching and cleanup.
    pub fn into_direct(self) -> std::result::Result<DirectResults, PreparedCursor> {
        match self {
            CursorPrepExecOutcome::Direct(d) => Ok(d),
            CursorPrepExecOutcome::Cursor(c) => Err(c),
        }
    }
}

/// The result sets a server returned inline from an AllowDirect
/// `sp_cursorprepexec`, together with the prepared handle that must still be
/// released.
///
/// No cursor was opened, so there is nothing to fetch or close — the buffered
/// [`results`](Self::results) are the complete response. Call
/// [`unprepare`](Self::unprepare) to release the prepared handle (and take
/// ownership of the result sets); dropping without unpreparing leaks the
/// handle until the connection closes and logs a warning.
#[derive(Debug)]
pub struct DirectResults {
    prepared_handle: PreparedHandle,
    results: Vec<DirectResultSet>,
    scrollopt: BitFlags<CursorScrollOptions>,
    ccopt: BitFlags<CursorConcurrencyOptions>,
    row_count: i32,
    released: bool,
}

impl DirectResults {
    /// The server-assigned prepared statement handle.
    pub fn prepared_handle(&self) -> PreparedHandle {
        self.prepared_handle
    }

    /// Scroll flags for the direct execution.
    ///
    /// SQL Server can omit cursor-related outputs on this path, in which case
    /// these are the options originally requested by the client.
    pub fn scroll_options(&self) -> BitFlags<CursorScrollOptions> {
        self.scrollopt
    }

    /// Concurrency flags for the direct execution.
    ///
    /// SQL Server can omit cursor-related outputs on this path, in which case
    /// these are the options originally requested by the client.
    pub fn concurrency_options(&self) -> BitFlags<CursorConcurrencyOptions> {
        self.ccopt
    }

    /// Server-reported row count, or `-1` if unknown.
    pub fn row_count(&self) -> i32 {
        self.row_count
    }

    /// The buffered result sets, in the order the server streamed them.
    pub fn results(&self) -> &[DirectResultSet] {
        &self.results
    }

    /// Release the prepared handle via `sp_unprepare`, returning the
    /// owned result sets.
    ///
    /// There is no cursor to close, so this only unprepares the statement.
    pub async fn unprepare<S>(
        mut self,
        client: &mut Client<S>,
    ) -> crate::Result<Vec<DirectResultSet>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let handle_param = build_unprepare_param(self.prepared_handle);
        // INFO 16954 means SQL Server created a direct prepared-statement
        // handle rather than a cursor-prepared handle, despite the original
        // sp_cursorprepexec request. Direct handles use sp_unprepare.
        client
            .send_rpc(RpcProcId::Unprepare, vec![handle_param])
            .await?;
        self.released = true;
        collect_rpc_outputs(&mut client.connection).await?;
        Ok(std::mem::take(&mut self.results))
    }
}

impl Drop for DirectResults {
    fn drop(&mut self) {
        if !self.released {
            event!(
                Level::WARN,
                prepared_handle = self.prepared_handle.as_i32(),
                "DirectResults dropped without unprepare; server-side prepared handle will leak until the connection closes"
            );
        }
    }
}

/// A single result set from an AllowDirect execution: its column metadata and
/// the rows the server streamed for it.
#[derive(Debug)]
pub struct DirectResultSet {
    columns: Arc<Vec<Column>>,
    rows: Vec<Row>,
}

impl DirectResultSet {
    /// The column metadata for this result set.
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The buffered rows, in order.
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// Consume this result set, returning its owned rows.
    pub fn into_rows(self) -> Vec<Row> {
        self.rows
    }
}

/// A server-side cursor handle.
///
/// Obtain via [`Client::open_cursor`](crate::Client::open_cursor). Page
/// through rows with [`fetch`](Self::fetch); release server-side resources
/// with [`close`](Self::close).
#[derive(Debug)]
pub struct Cursor {
    handle: CursorHandle,
    scrollopt: BitFlags<CursorScrollOptions>,
    ccopt: BitFlags<CursorConcurrencyOptions>,
    row_count: i32,
    /// `true` once the handle has been explicitly closed on the server
    /// (either via [`close`](Self::close) or set when close has at least
    /// reached the wire, so drain-time errors don't trigger a spurious
    /// drop-warning).
    closed: bool,
}

impl Cursor {
    /// The server-assigned cursor handle.
    pub fn handle(&self) -> CursorHandle {
        self.handle
    }

    /// Negotiated scroll flags, as returned by the server after
    /// `sp_cursoropen` — may differ from the options requested.
    pub fn scroll_options(&self) -> BitFlags<CursorScrollOptions> {
        self.scrollopt
    }

    /// Negotiated concurrency flags, as returned by the server after
    /// `sp_cursoropen`.
    pub fn concurrency_options(&self) -> BitFlags<CursorConcurrencyOptions> {
        self.ccopt
    }

    /// Server-reported row count. `-1` indicates "unknown" (e.g. dynamic
    /// cursors where the full row count is not known up front).
    pub fn row_count(&self) -> i32 {
        self.row_count
    }

    /// Fetch rows from the cursor.
    ///
    /// The [`Fetch`] enum encodes the valid combinations of direction and
    /// anchor arguments, e.g. `Fetch::Next { count: 10 }` or
    /// `Fetch::Absolute { row: 42, count: 5 }`.
    pub async fn fetch<'a, S>(
        &self,
        client: &'a mut Client<S>,
        fetch: Fetch,
    ) -> crate::Result<QueryStream<'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let rpc_params = build_cursorfetch_params(self.handle, fetch);
        client.send_rpc(RpcProcId::CursorFetch, rpc_params).await?;

        let ts = TokenStream::new(&mut client.connection);
        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;
        Ok(result)
    }

    fn close_params(&self) -> Vec<RpcParam<'static>> {
        vec![RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(self.handle.as_i32())),
        }]
    }

    /// Close the cursor and release its server-side resources.
    ///
    /// The cursor is flagged closed as soon as the `sp_cursorclose` packet
    /// reaches the wire, so an error surfaced while draining the response
    /// (cancellation, network glitch, etc.) does not trigger a spurious
    /// drop-time warning — the handle is gone from the server's perspective
    /// regardless.
    pub async fn close<S>(mut self, client: &mut Client<S>) -> crate::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        client
            .send_rpc(RpcProcId::CursorClose, self.close_params())
            .await?;
        // From the server's POV the handle is released the moment the RPC
        // is processed; anything surfaced while draining is informational.
        self.closed = true;
        collect_rpc_outputs(&mut client.connection).await?;
        Ok(())
    }
}

pub(crate) fn build_cursorfetch_params(
    handle: CursorHandle,
    fetch: Fetch,
) -> Vec<RpcParam<'static>> {
    let (fetch_bits, row_num, count) = fetch.encode();

    vec![
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(handle.as_i32())),
        },
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(fetch_bits)),
        },
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(row_num)),
        },
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(count)),
        },
    ]
}

impl Drop for Cursor {
    fn drop(&mut self) {
        if !self.closed {
            event!(
                Level::WARN,
                handle = self.handle.as_i32(),
                "Cursor dropped without close; server-side handle will leak until the connection closes"
            );
        }
    }
}

/// Build the RPC parameter list for `sp_cursoropen`:
/// `[@cursor OUT, @stmt, @scrollopt OUT (in/out), @ccopt OUT (in/out),
///   @rowcount OUT, @params nvarchar, @P1, @P2, ...]`.
///
/// The scroll / concurrency options are sent as input values (requested
/// behaviour) and come back via the same parameters as output (negotiated
/// behaviour) — so they carry the `ByRefValue` flag.
pub(crate) fn build_cursoropen_params<'a>(
    sql: Cow<'a, str>,
    options: CursorOpenOptions,
    param_defs: Cow<'a, str>,
    params: &[&'a dyn ToSql],
) -> Vec<RpcParam<'a>> {
    let mut rpc_params: Vec<RpcParam<'a>> = Vec::with_capacity(params.len() + 6);
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(0)),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: BitFlags::empty(),
        type_info: None,
        value: ColumnData::String(Some(sql)),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(flags_to_i32(options.scroll.bits()))),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(flags_to_i32(options.concurrency.bits()))),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(0)),
    });
    // @paramdef and bound params only get sent when the statement actually
    // has parameters. Passing an empty paramdef (or NULL) trips SQL Server's
    // T-SQL parser inside `sp_cursoropen`.
    if !param_defs.is_empty() {
        rpc_params.push(RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::String(Some(param_defs)),
        });
        for (i, p) in params.iter().enumerate() {
            rpc_params.push(RpcParam {
                name: Cow::Owned(format!("@P{}", i + 1)),
                flags: BitFlags::empty(),
                type_info: None,
                value: p.to_sql(),
            });
        }
    }
    rpc_params
}

/// Build the RPC parameter list for `sp_cursorprepexec`:
/// `[@prepared_handle OUT, @cursor OUT, @params, @stmt, @scrollopt OUT,
///   @ccopt OUT, @rowcount OUT, @P1, @P2, ...]`.
pub(crate) fn build_cursorprepexec_params<'a>(
    sql: Cow<'a, str>,
    options: CursorOpenOptions,
    param_defs: Cow<'a, str>,
    params: &[&'a dyn ToSql],
) -> Vec<RpcParam<'a>> {
    let mut rpc_params: Vec<RpcParam<'a>> = Vec::with_capacity(params.len() + 7);
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(0)),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(0)),
    });
    let param_defs = if param_defs.is_empty() {
        None
    } else {
        Some(param_defs)
    };
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: BitFlags::empty(),
        type_info: None,
        value: ColumnData::String(param_defs),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: BitFlags::empty(),
        type_info: None,
        value: ColumnData::String(Some(sql)),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(flags_to_i32(options.scroll.bits()))),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(flags_to_i32(options.concurrency.bits()))),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: RpcStatus::ByRefValue.into(),
        type_info: None,
        value: ColumnData::I32(Some(0)),
    });
    for (i, p) in params.iter().enumerate() {
        rpc_params.push(RpcParam {
            name: Cow::Owned(format!("@P{}", i + 1)),
            flags: BitFlags::empty(),
            type_info: None,
            value: p.to_sql(),
        });
    }
    rpc_params
}

pub(crate) fn build_unprepare_param(handle: PreparedHandle) -> RpcParam<'static> {
    RpcParam {
        name: Cow::Borrowed(""),
        flags: BitFlags::empty(),
        type_info: None,
        value: ColumnData::I32(Some(handle.as_i32())),
    }
}

/// Build a [`Cursor`] from the output parameters returned by `sp_cursoropen`.
///
/// Real SQL Server returns outputs with empty names in positional order
/// (@cursor, @scrollopt, @ccopt, @rowcount); the Tiberius self-hosted
/// harness names them. Match by name first, fall back to position.
pub(crate) fn cursor_from_outputs(outputs: &[OutputValue]) -> crate::Result<Cursor> {
    let lookup_named = |name: &str| -> Option<i32> {
        outputs
            .iter()
            .find(|o| !o.name().is_empty() && o.matches_name(name))
            .and_then(|o| o.get::<i32>().ok().flatten())
    };
    let by_pos = |idx: usize| -> Option<i32> {
        outputs.get(idx).and_then(|o| o.get::<i32>().ok().flatten())
    };

    let handle = lookup_named("cursor")
        .or_else(|| by_pos(0))
        .ok_or_else(|| {
            crate::Error::Protocol(
                "sp_cursoropen: missing @cursor output parameter in server response".into(),
            )
        })?;
    let scrollopt = lookup_named("scrollopt").or_else(|| by_pos(1)).unwrap_or(0);
    let ccopt = lookup_named("ccopt").or_else(|| by_pos(2)).unwrap_or(0);
    let row_count = lookup_named("rowcount").or_else(|| by_pos(3)).unwrap_or(-1);

    Ok(Cursor {
        handle: CursorHandle(handle),
        scrollopt: i32_to_scroll_flags(scrollopt),
        ccopt: i32_to_cc_flags(ccopt),
        row_count,
        closed: false,
    })
}

/// Build a [`PreparedCursor`] from `sp_cursorprepexec` output parameters.
///
/// SQL Server returns unnamed outputs in response order, while the self-hosted
/// tests can use names. Match names first, then fall back to arrival order.
/// These internal outputs are all `int`, so the TDS rule that moves large
/// object outputs to the end of the stream does not affect their order.
pub(crate) fn prepared_cursor_from_outputs(
    outputs: &[OutputValue],
    metadata: Option<Vec<Column>>,
) -> crate::Result<PreparedCursor> {
    let lookup_named = |name: &str| -> Option<i32> {
        outputs
            .iter()
            .find(|o| !o.name().is_empty() && o.matches_name(name))
            .and_then(|o| o.get::<i32>().ok().flatten())
    };
    let by_pos = |idx: usize| -> Option<i32> {
        outputs.get(idx).and_then(|o| o.get::<i32>().ok().flatten())
    };

    let prepared_handle = lookup_named("prepared_handle")
        .or_else(|| lookup_named("handle"))
        .or_else(|| by_pos(0))
        .ok_or_else(|| {
            crate::Error::Protocol(
                "sp_cursorprepexec: missing @prepared_handle output parameter".into(),
            )
        })?;
    if prepared_handle == 0 {
        return Err(crate::Error::Protocol(
            "sp_cursorprepexec: server returned a zero @prepared_handle".into(),
        ));
    }

    let cursor_handle = lookup_named("cursor")
        .or_else(|| by_pos(1))
        .ok_or_else(|| {
            crate::Error::Protocol("sp_cursorprepexec: missing @cursor output parameter".into())
        })?;
    if cursor_handle == 0 {
        return Err(crate::Error::Protocol(
            "sp_cursorprepexec: server returned a zero @cursor".into(),
        ));
    }

    let scrollopt = lookup_named("scrollopt").or_else(|| by_pos(2)).unwrap_or(0);
    let ccopt = lookup_named("ccopt").or_else(|| by_pos(3)).unwrap_or(0);
    let row_count = lookup_named("rowcount").or_else(|| by_pos(4)).unwrap_or(-1);

    let cursor = Cursor {
        handle: CursorHandle(cursor_handle),
        scrollopt: i32_to_scroll_flags(scrollopt),
        ccopt: i32_to_cc_flags(ccopt),
        row_count,
        closed: false,
    };

    Ok(PreparedCursor {
        prepared_handle: PreparedHandle::from_i32(prepared_handle),
        cursor: Some(cursor),
        cursor_handle: CursorHandle(cursor_handle),
        scrollopt: i32_to_scroll_flags(scrollopt),
        ccopt: i32_to_cc_flags(ccopt),
        row_count,
        metadata,
        released: false,
    })
}

const SQL_SERVER_INFO_EXECUTED_DIRECTLY: u32 = 16_954;

/// Interpret an `sp_cursorprepexec` response, distinguishing a normal
/// prepared cursor from an AllowDirect direct-result response.
///
/// SQL Server signals the AllowDirect fallback with INFO 16954 and may omit
/// the cursor ID and row-count outputs entirely. A response without that INFO
/// token is handled as a normal cursor response by
/// [`prepared_cursor_from_outputs`]; the buffered rows (a normal open streams
/// only metadata) are used solely to seed the cursor's cached metadata.
pub(crate) fn cursor_prep_exec_outcome(
    outputs: &[OutputValue],
    result_sets: Vec<BufferedResultSet>,
    infos: &[TokenInfo],
    requested_options: CursorOpenOptions,
) -> crate::Result<CursorPrepExecOutcome> {
    let lookup_named = |name: &str| -> Option<i32> {
        outputs
            .iter()
            .find(|o| !o.name().is_empty() && o.matches_name(name))
            .and_then(|o| o.get::<i32>().ok().flatten())
    };
    let by_pos = |idx: usize| -> Option<i32> {
        outputs.get(idx).and_then(|o| o.get::<i32>().ok().flatten())
    };

    let prepared_handle = lookup_named("prepared_handle")
        .or_else(|| lookup_named("handle"))
        .or_else(|| by_pos(0))
        .ok_or_else(|| {
            crate::Error::Protocol(
                "sp_cursorprepexec: missing @prepared_handle output parameter".into(),
            )
        })?;
    if prepared_handle == 0 {
        return Err(crate::Error::Protocol(
            "sp_cursorprepexec: server returned a zero @prepared_handle".into(),
        ));
    }

    if infos
        .iter()
        .any(|info| info.number == SQL_SERVER_INFO_EXECUTED_DIRECTLY)
    {
        // On this response SQL Server can omit @cursor and @rowcount. Do not
        // positionally reinterpret whichever sparse output happens to follow
        // @prepared_handle. Named cursor-option outputs are safe to use; when
        // real SQL Server leaves names empty, retain the requested options.
        let scrollopt = lookup_named("scrollopt")
            .unwrap_or_else(|| flags_to_i32(requested_options.scroll().bits()));
        let ccopt = lookup_named("ccopt")
            .unwrap_or_else(|| flags_to_i32(requested_options.concurrency().bits()));
        let row_count = lookup_named("rowcount").unwrap_or(-1);

        let results = result_sets
            .into_iter()
            .map(|rs| DirectResultSet {
                columns: rs.columns,
                rows: rs.rows,
            })
            .collect();

        return Ok(CursorPrepExecOutcome::Direct(DirectResults {
            prepared_handle: PreparedHandle::from_i32(prepared_handle),
            results,
            scrollopt: i32_to_scroll_flags(scrollopt),
            ccopt: i32_to_cc_flags(ccopt),
            row_count,
            released: false,
        }));
    }

    // Preserve the pre-AllowDirect behaviour: seed the cursor's cached
    // metadata from the first result set (only non-empty sets are buffered, so
    // `first` is the first non-empty COLMETADATA).
    let metadata = result_sets.first().map(|rs| (*rs.columns).clone());
    Ok(CursorPrepExecOutcome::Cursor(prepared_cursor_from_outputs(
        outputs, metadata,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{
        BaseMetaDataColumn, FixedLenType, TokenReturnValue, TokenRow, TypeInfo,
    };

    #[test]
    fn fetch_encodes_next() {
        assert_eq!(Fetch::Next { count: 10 }.encode(), (0x0002, 0, 10));
    }

    #[test]
    fn fetch_encodes_absolute_with_row() {
        assert_eq!(
            Fetch::Absolute { row: 42, count: 5 }.encode(),
            (0x0010, 42, 5)
        );
    }

    #[test]
    fn fetch_encodes_relative_with_negative_offset() {
        assert_eq!(
            Fetch::Relative {
                offset: -3,
                count: 1
            }
            .encode(),
            (0x0020, -3, 1)
        );
    }

    #[test]
    fn fetch_encodes_refresh_ignores_row_num() {
        assert_eq!(Fetch::Refresh { count: 1 }.encode(), (0x0080, 0, 1));
    }

    #[test]
    fn cursorfetch_params_encode_metadata_probe() {
        let params = build_cursorfetch_params(CursorHandle(1234), Fetch::Next { count: 0 });
        let values: Vec<_> = params
            .iter()
            .map(|p| match &p.value {
                ColumnData::I32(Some(v)) => *v,
                other => panic!("expected i32 cursorfetch param, got {:?}", other),
            })
            .collect();

        assert_eq!(values, vec![1234, 0x0002, 0, 0]);
    }

    #[test]
    fn open_options_combine_scroll_flags() {
        let opts = CursorOpenOptions::new(
            CursorScrollOptions::ParameterizedStmt | CursorScrollOptions::ForwardOnly,
            CursorConcurrencyOptions::ReadOnly,
        );
        let bits = opts.scroll().bits();
        assert!(bits & (CursorScrollOptions::ParameterizedStmt as u32) != 0);
        assert!(bits & (CursorScrollOptions::ForwardOnly as u32) != 0);
    }

    #[test]
    fn default_options_are_forward_only_readonly() {
        let opts = CursorOpenOptions::default();
        assert!(opts.scroll().contains(CursorScrollOptions::ForwardOnly));
        assert!(opts
            .concurrency()
            .contains(CursorConcurrencyOptions::ReadOnly));
    }

    #[test]
    fn i32_round_trip_through_scroll_flags() {
        // Unknown bits are truncated (don't round-trip) — that's by design:
        // we don't want to panic on a server that sends proprietary bits.
        let flags = i32_to_scroll_flags(0x0004);
        assert!(flags.contains(CursorScrollOptions::ForwardOnly));
    }

    fn output(name: &str, value: i32) -> OutputValue {
        output_at(name, 0, value)
    }

    fn output_at(name: &str, ordinal: u16, value: i32) -> OutputValue {
        TokenReturnValue {
            param_ordinal: ordinal,
            param_name: name.to_string(),
            udf: false,
            meta: BaseMetaDataColumn {
                user_type: 0,
                flags: BitFlags::empty(),
                ty: TypeInfo::FixedLen(FixedLenType::Int4),
                table_name: None,
            },
            value: ColumnData::I32(Some(value)),
        }
        .into()
    }

    fn direct_info() -> Vec<TokenInfo> {
        vec![TokenInfo::new(
            SQL_SERVER_INFO_EXECUTED_DIRECTLY,
            1,
            10,
            "Executing SQL directly; no cursor.",
            "srv",
            "",
            1,
        )]
    }

    fn direct_options() -> CursorOpenOptions {
        CursorOpenOptions::new(
            CursorScrollOptions::ForwardOnly,
            CursorConcurrencyOptions::ReadOnly | CursorConcurrencyOptions::AllowDirect,
        )
    }

    #[test]
    fn cursorprepexec_params_match_trace_order_and_outputs() {
        let p1: &dyn ToSql = &42i32;
        let params = build_cursorprepexec_params(
            Cow::Borrowed("SELECT @P1"),
            CursorOpenOptions::default(),
            Cow::Borrowed("@P1 int"),
            &[p1],
        );

        assert_eq!(params.len(), 8);
        assert!(params[0].flags.contains(RpcStatus::ByRefValue));
        assert!(params[1].flags.contains(RpcStatus::ByRefValue));
        assert!(matches!(params[2].value, ColumnData::String(Some(ref s)) if s == "@P1 int"));
        assert!(matches!(params[3].value, ColumnData::String(Some(ref s)) if s == "SELECT @P1"));
        assert!(params[4].flags.contains(RpcStatus::ByRefValue));
        assert!(params[5].flags.contains(RpcStatus::ByRefValue));
        assert!(params[6].flags.contains(RpcStatus::ByRefValue));
        assert_eq!(params[7].name, "@P1");
    }

    #[test]
    fn cursorprepexec_params_encode_parameterized_stmt_scroll_option() {
        let p1: &dyn ToSql = &42i32;
        let params = build_cursorprepexec_params(
            Cow::Borrowed("SELECT @P1"),
            CursorOpenOptions::new(
                CursorScrollOptions::ParameterizedStmt | CursorScrollOptions::ForwardOnly,
                CursorConcurrencyOptions::ReadOnly,
            ),
            Cow::Borrowed("@P1 int"),
            &[p1],
        );

        assert!(matches!(
            params[4].value,
            ColumnData::I32(Some(v))
                if v == (CursorScrollOptions::ParameterizedStmt as i32
                    | CursorScrollOptions::ForwardOnly as i32)
        ));
    }

    #[test]
    fn cursorprepexec_sends_null_param_defs_slot() {
        let params = build_cursorprepexec_params(
            Cow::Borrowed("SELECT 1"),
            CursorOpenOptions::default(),
            Cow::Borrowed(""),
            &[],
        );
        assert!(matches!(params[2].value, ColumnData::String(None)));
    }

    #[test]
    fn prepared_cursor_parses_response_order_when_ordinals_mislead() {
        // Deliberately misleading ordinals prove that unnamed SQL Server
        // outputs are interpreted by response order, not ParamOrdinal.
        let outputs = vec![
            output_at("", 0, 11),
            output_at("", 1, 22),
            output_at("", 99, CursorScrollOptions::ForwardOnly as i32),
            output_at("", 2, CursorConcurrencyOptions::ReadOnly as i32),
            output_at("", 5, 3),
        ];

        let pc = prepared_cursor_from_outputs(&outputs, None).unwrap();
        assert_eq!(pc.prepared_handle().as_i32(), 11);
        assert_eq!(pc.cursor_handle().as_i32(), 22);
        assert!(pc
            .scroll_options()
            .contains(CursorScrollOptions::ForwardOnly));
        assert!(pc
            .concurrency_options()
            .contains(CursorConcurrencyOptions::ReadOnly));
        assert_eq!(pc.row_count(), 3);
    }

    #[test]
    fn prepared_cursor_parses_named_outputs() {
        let outputs = vec![
            output("@cursor", 22),
            output("@rowcount", 3),
            output("@prepared_handle", 11),
            output("@ccopt", CursorConcurrencyOptions::ReadOnly as i32),
            output("@scrollopt", CursorScrollOptions::ForwardOnly as i32),
        ];

        let pc = prepared_cursor_from_outputs(&outputs, None).unwrap();
        assert_eq!(pc.prepared_handle().as_i32(), 11);
        assert_eq!(pc.cursor_handle().as_i32(), 22);
        assert_eq!(pc.row_count(), 3);
    }

    #[test]
    fn prepared_cursor_keeps_initial_metadata() {
        let outputs = vec![
            output("", 11),
            output("", 22),
            output("", CursorScrollOptions::ForwardOnly as i32),
            output("", CursorConcurrencyOptions::ReadOnly as i32),
            output("", 3),
        ];
        let metadata = vec![Column::new("v".to_string(), crate::ColumnType::Int4)];

        let pc = prepared_cursor_from_outputs(&outputs, Some(metadata)).unwrap();

        let metadata = pc.metadata.as_ref().unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].name(), "v");
    }

    #[test]
    fn unprepare_param_contains_prepared_handle() {
        let param = build_unprepare_param(PreparedHandle::from_i32(77));
        assert_eq!(param.name, "");
        assert!(param.flags.is_empty());
        assert!(matches!(param.value, ColumnData::I32(Some(77))));
    }

    fn direct_set(result_index: usize, values: &[i32]) -> BufferedResultSet {
        let columns = Arc::new(vec![Column::new("v".to_string(), crate::ColumnType::Int4)]);
        let rows = values
            .iter()
            .map(|&v| {
                let mut data = TokenRow::new();
                data.push(ColumnData::I32(Some(v)));
                Row {
                    columns: columns.clone(),
                    data,
                    result_index,
                }
            })
            .collect();
        BufferedResultSet { columns, rows }
    }

    #[test]
    fn cursor_prep_exec_outcome_returns_cursor_for_nonzero_cursor() {
        let outputs = vec![
            output_at("", 0, 11),
            output_at("", 1, 22),
            output_at("", 77, CursorScrollOptions::ForwardOnly as i32),
            output_at("", 2, CursorConcurrencyOptions::ReadOnly as i32),
            output_at("", 5, 3),
        ];

        let outcome =
            cursor_prep_exec_outcome(&outputs, Vec::new(), &[], CursorOpenOptions::default())
                .unwrap();
        assert!(!outcome.is_direct());
        assert_eq!(outcome.prepared_handle().as_i32(), 11);

        let cursor = outcome.into_cursor().expect("expected cursor outcome");
        assert_eq!(cursor.prepared_handle().as_i32(), 11);
        assert_eq!(cursor.cursor_handle().as_i32(), 22);
        assert_eq!(cursor.row_count(), 3);
    }

    #[test]
    fn cursor_prep_exec_outcome_returns_direct_for_info_16954_without_cursor_outputs() {
        // The later outputs carry ordinals that would be mistaken for the
        // prepared handle and cursor by an ordinal-driven parser.
        let outputs = vec![
            output_at("", 0, 11),
            output_at("", 1, CursorScrollOptions::Dynamic as i32),
            output_at("", 2, CursorConcurrencyOptions::OptimisticCc as i32),
        ];
        let infos = direct_info();

        let outcome = cursor_prep_exec_outcome(
            &outputs,
            vec![direct_set(0, &[1, 2, 3])],
            &infos,
            direct_options(),
        )
        .unwrap();
        assert!(outcome.is_direct());
        assert_eq!(outcome.prepared_handle().as_i32(), 11);

        let direct = outcome.into_direct().expect("expected direct outcome");
        assert_eq!(direct.prepared_handle().as_i32(), 11);
        assert_eq!(direct.row_count(), -1);
        assert!(direct
            .scroll_options()
            .contains(CursorScrollOptions::ForwardOnly));
        assert!(direct
            .concurrency_options()
            .contains(CursorConcurrencyOptions::AllowDirect));
        assert_eq!(direct.results().len(), 1);
        assert_eq!(direct.results()[0].columns().len(), 1);
        assert_eq!(direct.results()[0].columns()[0].name(), "v");
        assert_eq!(direct.results()[0].rows().len(), 3);
        assert_eq!(direct.results()[0].rows()[0].get::<i32, _>(0), Some(1));
        assert_eq!(direct.results()[0].rows()[2].get::<i32, _>(0), Some(3));
    }

    #[test]
    fn into_cursor_preserves_direct_results_on_mismatch() {
        let outputs = vec![output_at("", 0, 11)];
        let infos = direct_info();
        let outcome = cursor_prep_exec_outcome(
            &outputs,
            vec![direct_set(0, &[7])],
            &infos,
            direct_options(),
        )
        .unwrap();

        let mut direct = outcome
            .into_cursor()
            .expect_err("expected intact direct results");
        assert_eq!(direct.prepared_handle().as_i32(), 11);
        assert_eq!(direct.results().len(), 1);
        assert_eq!(direct.results()[0].rows()[0].get::<i32, _>(0), Some(7));

        // This is a synthetic unit-test handle, so suppress the intentional
        // leak warning after proving the alternate variant survived intact.
        direct.released = true;
    }

    #[test]
    fn into_direct_preserves_prepared_cursor_on_mismatch() {
        let outputs = vec![output_at("", 0, 11), output_at("", 0, 22)];
        let outcome =
            cursor_prep_exec_outcome(&outputs, Vec::new(), &[], CursorOpenOptions::default())
                .unwrap();

        let mut cursor = outcome
            .into_direct()
            .expect_err("expected intact prepared cursor");
        assert_eq!(cursor.prepared_handle().as_i32(), 11);
        assert_eq!(cursor.cursor_handle().as_i32(), 22);

        // These are synthetic unit-test handles, so suppress the intentional
        // leak warnings after proving the alternate variant survived intact.
        cursor.released = true;
        if let Some(inner) = cursor.cursor.as_mut() {
            inner.closed = true;
        }
    }

    #[test]
    fn cursor_prep_exec_outcome_preserves_multiple_direct_sets_in_order() {
        let outputs = vec![output_at("", 0, 11)];
        let infos = direct_info();

        let outcome = cursor_prep_exec_outcome(
            &outputs,
            vec![direct_set(0, &[1, 2, 3]), direct_set(1, &[4, 5])],
            &infos,
            direct_options(),
        )
        .unwrap();
        let direct = outcome.into_direct().expect("expected direct outcome");

        assert_eq!(direct.results().len(), 2);
        assert_eq!(direct.results()[0].rows().len(), 3);
        assert_eq!(direct.results()[0].rows()[0].get::<i32, _>(0), Some(1));
        assert_eq!(direct.results()[1].rows().len(), 2);
        assert_eq!(direct.results()[1].rows()[0].get::<i32, _>(0), Some(4));
        assert_eq!(direct.results()[1].rows()[1].get::<i32, _>(0), Some(5));
    }

    #[test]
    fn direct_result_set_into_rows_returns_owned_rows() {
        let columns = Arc::new(vec![Column::new("v".to_string(), crate::ColumnType::Int4)]);
        let mut data = TokenRow::new();
        data.push(ColumnData::I32(Some(9)));
        let rows = vec![Row {
            columns: columns.clone(),
            data,
            result_index: 0,
        }];
        let rs = DirectResultSet { columns, rows };

        assert_eq!(rs.columns().len(), 1);
        assert_eq!(rs.rows().len(), 1);

        let owned = rs.into_rows();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].get::<i32, _>(0), Some(9));
    }

    #[test]
    fn cursor_prep_exec_outcome_errors_on_zero_prepared_handle() {
        let outputs = vec![output("", 0), output("", 0)];
        let err = cursor_prep_exec_outcome(&outputs, Vec::new(), &[], CursorOpenOptions::default())
            .unwrap_err();
        assert!(matches!(err, crate::Error::Protocol(_)));
    }

    #[test]
    fn cursor_prep_exec_outcome_errors_on_missing_cursor() {
        // A prepared handle but no @cursor anywhere falls through to the normal
        // cursor path, which reports the missing-@cursor protocol error.
        let outputs = vec![output("@prepared_handle", 11)];
        match cursor_prep_exec_outcome(&outputs, Vec::new(), &[], CursorOpenOptions::default())
            .unwrap_err()
        {
            crate::Error::Protocol(msg) => {
                assert!(msg.contains("@cursor"), "unexpected message: {msg}")
            }
            other => panic!("expected protocol error, got {:?}", other),
        }
    }
}
