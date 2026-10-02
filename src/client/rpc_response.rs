//! Shared helpers for consuming RPC responses on the client side.
//!
//! Prepared-statement and cursor APIs issue RPC calls whose responses arrive
//! as a mix of optional result sets, zero or more `RETURNVALUE` tokens, and a
//! `RETURNSTATUS` + `DONEPROC` pair. This module provides the plumbing for
//! extracting those pieces without duplicating token-walking logic across
//! every new helper.

use crate::client::Connection;
use crate::tds::codec::{
    ColumnData, DoneStatus, TokenColInfo, TokenColMetaData, TokenColName, TokenDone,
    TokenEnvChange, TokenError, TokenInfo, TokenOrder, TokenReturnValue, TokenSessionState,
    TokenTabName, TypeInfo,
};
use crate::tds::stream::{ReceivedToken, TokenStream};
use crate::{Column, FromSql, Row, SqlReadBytes, TokenType};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::{Stream, TryStreamExt};
use std::convert::TryFrom;
use std::sync::Arc;

/// A single `RETURNVALUE` token surfaced to the client.
///
/// Use [`get`](Self::get) to decode the value through the same
/// [`FromSql`](crate::FromSql) machinery that [`Row::get`](crate::Row::get)
/// uses, so callers don't need to pattern-match on the internal
/// [`ColumnData`] enum.
#[derive(Debug, Clone)]
pub struct OutputValue {
    name: String,
    ordinal: u16,
    type_info: TypeInfo,
    value: ColumnData<'static>,
}

impl OutputValue {
    /// The parameter name reported by the server. Servers commonly return an
    /// empty string for positional output parameters and include the `@`
    /// prefix for named ones.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Positional ordinal assigned by the server. Ordering is not guaranteed
    /// to be stable across providers; prefer matching on [`name`](Self::name)
    /// when the server populates it.
    pub fn ordinal(&self) -> u16 {
        self.ordinal
    }

    /// The wire type the server used for this value (e.g. precision/scale
    /// for `NUMERIC`, the declared length for `VARCHAR`/`VARBINARY`).
    pub fn type_info(&self) -> &TypeInfo {
        &self.type_info
    }

    /// Decode the value as `T` via [`FromSql`].
    ///
    /// Returns `Ok(None)` if the value is SQL `NULL`, `Ok(Some(_))` on a
    /// successful conversion, or `Err(Conversion)` if the stored type
    /// doesn't map to `T`.
    pub fn get<'a, T>(&'a self) -> crate::Result<Option<T>>
    where
        T: FromSql<'a>,
    {
        T::from_sql(&self.value)
    }

    /// Borrow the raw underlying value. Most callers should prefer
    /// [`get`](Self::get); this escape hatch exists for users that need to
    /// inspect an unusual type directly.
    pub fn raw(&self) -> &ColumnData<'static> {
        &self.value
    }

    /// Case-insensitive name compare, ignoring a leading `@` on either side.
    ///
    /// Returns `false` if either name is empty after prefix-stripping — the
    /// server frequently emits empty names for positional outputs, and those
    /// should not match arbitrary lookup keys.
    pub fn matches_name(&self, name: &str) -> bool {
        let a = self.name.strip_prefix('@').unwrap_or(&self.name);
        let b = name.strip_prefix('@').unwrap_or(name);
        if a.is_empty() || b.is_empty() {
            return false;
        }
        a.eq_ignore_ascii_case(b)
    }
}

impl From<TokenReturnValue> for OutputValue {
    fn from(tok: TokenReturnValue) -> Self {
        Self {
            name: tok.param_name,
            ordinal: tok.param_ordinal,
            type_info: tok.meta.ty,
            value: tok.value,
        }
    }
}

/// Collect the output parameters + return status from an RPC call that
/// produces no result sets (`sp_prepare`, `sp_unprepare`, `sp_cursoropen`,
/// `sp_cursorclose`).
///
/// The stream is drained until a `DONEPROC` / `DONE` token without the
/// `More` flag is observed. Any `TokenError` is captured (first one wins)
/// and returned once the `DONEPROC` is consumed so the connection is left
/// in a clean state.
pub(crate) async fn collect_rpc_outputs<S>(
    conn: &mut Connection<S>,
) -> crate::Result<(Vec<OutputValue>, Option<u32>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (outputs, status, _) = collect_rpc_outputs_with_metadata(conn).await?;
    Ok((outputs, status))
}

pub(crate) async fn collect_rpc_outputs_with_metadata<S>(
    conn: &mut Connection<S>,
) -> crate::Result<(Vec<OutputValue>, Option<u32>, Option<Vec<Column>>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ts = TokenStream::new(conn);
    let stream = ts.try_unfold();
    collect_rpc_outputs_with_metadata_from_stream(stream).await
}

/// Lower-level variant that drains an arbitrary token stream. Exists to
/// make `collect_rpc_outputs` unit-testable with synthetic inputs.
#[cfg(test)]
pub(crate) async fn collect_rpc_outputs_from_stream<S>(
    stream: S,
) -> crate::Result<(Vec<OutputValue>, Option<u32>)>
where
    S: Stream<Item = crate::Result<ReceivedToken>> + Unpin,
{
    let (outputs, status, _) = collect_rpc_outputs_with_metadata_from_stream(stream).await?;
    Ok((outputs, status))
}

async fn collect_rpc_outputs_with_metadata_from_stream<S>(
    mut stream: S,
) -> crate::Result<(Vec<OutputValue>, Option<u32>, Option<Vec<Column>>)>
where
    S: Stream<Item = crate::Result<ReceivedToken>> + Unpin,
{
    let mut outputs = Vec::new();
    let mut status = None;
    let mut metadata = None;
    let mut last_error: Option<crate::Error> = None;

    while let Some(token) = stream.try_next().await? {
        match token {
            ReceivedToken::NewResultset(meta) => {
                if metadata.is_none() {
                    let columns = meta.columns().collect::<Vec<_>>();
                    if !columns.is_empty() {
                        metadata = Some(columns);
                    }
                }
            }
            ReceivedToken::ReturnValue(rv) => outputs.push((*rv).into()),
            ReceivedToken::ReturnStatus(s) => status = Some(s),
            ReceivedToken::Error(e) => {
                if last_error.is_none() {
                    last_error = Some(crate::Error::Server(e));
                }
            }
            ReceivedToken::DoneProc(done) | ReceivedToken::Done(done) => {
                // DoneProc/Done without the `More` flag marks the end of the
                // RPC response.
                if !done.status().contains(DoneStatus::More) {
                    break;
                }
            }
            // Intermediate DoneInProc can appear if the server emits them
            // even for no-result ops; skip.
            ReceivedToken::DoneInProc(_) => {}
            _ => {}
        }
    }

    if let Some(err) = last_error {
        return Err(err);
    }

    Ok((outputs, status, metadata))
}

/// Reads the response to `calls` RPCs sent with `Client::send_rpc_batch`,
/// returning each call's outcome. The outer error covers transport and stream
/// failures; a server error belongs to the call whose `DONEPROC` follows it.
pub(crate) async fn collect_rpc_batch_results<S>(
    conn: &mut Connection<S>,
    calls: usize,
) -> crate::Result<Vec<crate::Result<()>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ts = TokenStream::new(conn);
    collect_rpc_batch_results_from_stream(ts.try_unfold(), calls).await
}

async fn collect_rpc_batch_results_from_stream<S>(
    mut stream: S,
    calls: usize,
) -> crate::Result<Vec<crate::Result<()>>>
where
    S: Stream<Item = crate::Result<ReceivedToken>> + Unpin,
{
    let mut results = Vec::with_capacity(calls);
    let mut error = None;
    while results.len() < calls {
        let Some(token) = stream.try_next().await? else {
            break;
        };
        match token {
            ReceivedToken::Error(e) => {
                error.get_or_insert(crate::Error::Server(e));
            }
            ReceivedToken::DoneProc(_) => {
                results.push(error.take().map_or(Ok(()), Err));
            }
            // A plain DONE without `More` ends the whole response, for
            // example when the server rejects the request before any call.
            ReceivedToken::Done(done) if !done.status().contains(DoneStatus::More) => break,
            _ => {}
        }
    }
    if results.len() < calls {
        let reason = error.unwrap_or_else(|| {
            crate::Error::Protocol("RPC batch response ended before every call completed".into())
        });
        let message = reason.to_string();
        results.push(Err(reason));
        while results.len() < calls {
            results.push(Err(crate::Error::Protocol(message.clone().into())));
        }
    }
    Ok(results)
}

/// A single result set buffered from an RPC response: its column metadata and
/// every row that belongs to it.
///
/// Unlike [`collect_rpc_outputs_with_metadata`], which keeps only the first
/// COLMETADATA and discards row data, this retains the rows so callers such as
/// the AllowDirect `sp_cursorprepexec` path — and [`Client::call_procedure`](
/// crate::Client::call_procedure) — can own the streamed result sets.
#[derive(Debug)]
pub struct BufferedResultSet {
    /// The result set's column metadata.
    pub columns: Arc<Vec<Column>>,
    /// Every row belonging to this result set, in server order.
    pub rows: Vec<Row>,
}

/// Drain an RPC response, buffering every result set (metadata + rows, in
/// order) alongside the `RETURNVALUE` outputs and the return status.
///
/// This is the row-preserving counterpart of
/// [`collect_rpc_outputs_with_metadata`]: `sp_cursorprepexec` normally streams
/// only COLMETADATA on open (rows arrive later via `sp_cursorfetch`), but when
/// the server selects the AllowDirect fast path it streams the result sets
/// inline, and those rows must be kept.
pub(crate) async fn collect_rpc_result_sets<S>(
    conn: &mut Connection<S>,
) -> crate::Result<(
    Vec<BufferedResultSet>,
    Vec<OutputValue>,
    Option<u32>,
    Vec<TokenInfo>,
)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ts = TokenStream::new(conn);
    let stream = ts.try_unfold();
    collect_rpc_result_sets_from_stream_with_mode(stream, RowCollectionMode::BufferRows).await
}

/// Drain an RPC response while retaining result-set metadata and response
/// values, but dropping each row after it has been decoded.
pub(crate) async fn collect_rpc_result_sets_without_rows<S>(
    conn: &mut Connection<S>,
) -> crate::Result<(
    Vec<BufferedResultSet>,
    Vec<OutputValue>,
    Option<u32>,
    Vec<TokenInfo>,
)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ts = TokenStream::new(conn);
    let stream = ts.try_unfold();
    collect_rpc_result_sets_from_stream_with_mode(stream, RowCollectionMode::DiscardRows).await
}

#[cfg(test)]
/// Lower-level variant that drains an arbitrary token stream, so the buffering
/// logic can be unit-tested with synthetic inputs (mirrors
/// [`collect_rpc_outputs_from_stream`]).
async fn collect_rpc_result_sets_from_stream<S>(
    stream: S,
) -> crate::Result<(
    Vec<BufferedResultSet>,
    Vec<OutputValue>,
    Option<u32>,
    Vec<TokenInfo>,
)>
where
    S: Stream<Item = crate::Result<ReceivedToken>> + Unpin,
{
    collect_rpc_result_sets_from_stream_with_mode(stream, RowCollectionMode::BufferRows).await
}

#[derive(Clone, Copy)]
enum RowCollectionMode {
    BufferRows,
    DiscardRows,
}

async fn collect_rpc_result_sets_from_stream_with_mode<S>(
    mut stream: S,
    row_mode: RowCollectionMode,
) -> crate::Result<(
    Vec<BufferedResultSet>,
    Vec<OutputValue>,
    Option<u32>,
    Vec<TokenInfo>,
)>
where
    S: Stream<Item = crate::Result<ReceivedToken>> + Unpin,
{
    let mut results: Vec<BufferedResultSet> = Vec::new();
    let mut columns: Option<Arc<Vec<Column>>> = None;
    let mut current: Vec<Row> = Vec::new();
    let mut outputs: Vec<OutputValue> = Vec::new();
    let mut status = None;
    let mut infos = Vec::new();
    let mut last_error: Option<crate::Error> = None;

    // Flush the in-progress result set into `results`, but only if it carries
    // column metadata — a result set is defined by its COLMETADATA, so an
    // empty-COLMETADATA placeholder (0 columns) is dropped rather than recorded.
    fn flush(
        results: &mut Vec<BufferedResultSet>,
        columns: &mut Option<Arc<Vec<Column>>>,
        current: &mut Vec<Row>,
    ) {
        if let Some(cols) = columns.take() {
            if !cols.is_empty() {
                results.push(BufferedResultSet {
                    columns: cols,
                    rows: std::mem::take(current),
                });
            } else {
                current.clear();
            }
        }
    }

    while let Some(token) = stream.try_next().await? {
        match token {
            ReceivedToken::NewResultset(meta) => {
                flush(&mut results, &mut columns, &mut current);
                columns = Some(Arc::new(meta.columns().collect::<Vec<_>>()));
            }
            ReceivedToken::Row(data) => {
                if let RowCollectionMode::BufferRows = row_mode {
                    if let Some(cols) = &columns {
                        current.push(Row {
                            columns: cols.clone(),
                            data,
                            // The index this set will occupy once flushed.
                            result_index: results.len(),
                        });
                    }
                }
            }
            ReceivedToken::ReturnValue(rv) => outputs.push((*rv).into()),
            ReceivedToken::ReturnStatus(s) => status = Some(s),
            ReceivedToken::Info(info) => infos.push(info),
            ReceivedToken::Error(e) => {
                if last_error.is_none() {
                    last_error = Some(crate::Error::Server(e));
                }
            }
            ReceivedToken::DoneInProc(done) => {
                if done.status().contains(DoneStatus::Attention) {
                    return Err(crate::Error::Canceled);
                }
                // A DoneInProc without `More` closes one statement's result set
                // inside the proc; more tokens (ReturnValue, DoneProc) follow.
                if !done.status().contains(DoneStatus::More) {
                    flush(&mut results, &mut columns, &mut current);
                }
            }
            ReceivedToken::DoneProc(done) | ReceivedToken::Done(done)
                if done.status().contains(DoneStatus::Attention) =>
            {
                return Err(crate::Error::Canceled);
            }
            ReceivedToken::DoneProc(done) | ReceivedToken::Done(done)
                if !done.status().contains(DoneStatus::More) =>
            {
                flush(&mut results, &mut columns, &mut current);
                break;
            }
            _ => {}
        }
    }

    if let Some(err) = last_error {
        return Err(err);
    }

    Ok((results, outputs, status, infos))
}

/// Drain a metadata-only cursor-fetch RPC response without constructing a
/// [`QueryStream`](crate::QueryStream). The metadata probe requests zero rows,
/// so this walker returns as soon as it sees the first non-empty COLMETADATA
/// and then asks the connection to clean the rest of the response.
pub(crate) async fn collect_metadata_only_rpc<S>(
    conn: &mut Connection<S>,
) -> crate::Result<Vec<Column>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut last_error = None;

    loop {
        // Race the token-byte read against cancellation. A metadata probe that
        // stalls (e.g. server lock contention) would otherwise park here with
        // no way to observe a `cancel()`. On cancellation the attention signal
        // has been sent; drain to the Done+Attention ack and surface it.
        let ty_byte = match conn.read_u8_or_cancel().await? {
            Some(byte) => byte,
            None => {
                TokenStream::new_with_attention(conn)
                    .flush_to_attention()
                    .await?;
                return Err(crate::Error::Canceled);
            }
        };
        let ty = TokenType::try_from(ty_byte).map_err(|_| {
            crate::Error::Protocol(format!("invalid token type {:x}", ty_byte).into())
        })?;

        match ty {
            TokenType::ColMetaData => {
                let metadata = TokenColMetaData::decode(conn).await?;
                if !metadata.columns.is_empty() {
                    let columns = metadata.columns().collect();
                    conn.context_mut().set_last_meta(Arc::new(metadata));
                    conn.flush_stream().await?;
                    return Ok(columns);
                }
            }
            TokenType::ReturnStatus => {
                let _ = conn.read_u32_le().await?;
            }
            TokenType::ReturnValue => {
                let _ = TokenReturnValue::decode(conn).await?;
            }
            TokenType::DoneInProc => {
                let _ = TokenDone::decode(conn).await?;
            }
            TokenType::DoneProc | TokenType::Done => {
                let done = TokenDone::decode(conn).await?;
                if !done.status().contains(DoneStatus::More) {
                    break;
                }
            }
            TokenType::Error => {
                let err = TokenError::decode(conn).await?;
                if last_error.is_none() {
                    last_error = Some(crate::Error::Server(err));
                }
            }
            TokenType::Info => {
                let _ = TokenInfo::decode(conn).await?;
            }
            TokenType::Order => {
                let _ = TokenOrder::decode(conn).await?;
            }
            TokenType::ColName => {
                let _ = TokenColName::decode(conn).await?;
            }
            TokenType::ColInfo => {
                let _ = TokenColInfo::decode(conn).await?;
            }
            TokenType::TabName => {
                let _ = TokenTabName::decode(conn).await?;
            }
            TokenType::EnvChange => {
                let _ = TokenEnvChange::decode(conn).await?;
            }
            TokenType::SessionState => {
                let _ = TokenSessionState::decode(conn).await?;
            }
            TokenType::Row | TokenType::NbcRow => {
                return Err(crate::Error::Protocol(
                    "metadata cursor fetch returned row data before non-empty COLMETADATA".into(),
                ));
            }
            other => {
                return Err(crate::Error::Protocol(
                    format!(
                        "metadata-only cursor fetch returned unexpected token {:?}",
                        other
                    )
                    .into(),
                ));
            }
        }
    }

    if let Some(err) = last_error {
        return Err(err);
    }

    Err(crate::Error::Protocol(
        "metadata cursor fetch returned no non-empty COLMETADATA".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{
        BaseMetaDataColumn, FixedLenType, MetaDataColumn, TokenDone, TokenError, TokenRow, TypeInfo,
    };
    use enumflags2::BitFlags;
    use futures_util::stream::iter;

    fn mk_done_proc_final() -> ReceivedToken {
        ReceivedToken::DoneProc(TokenDone::with_rows(0))
    }

    fn mk_done_proc_more() -> ReceivedToken {
        ReceivedToken::DoneProc(TokenDone::with_more_rows(0))
    }

    fn synthetic(tokens: Vec<ReceivedToken>) -> impl Stream<Item = crate::Result<ReceivedToken>> {
        iter(tokens.into_iter().map(Ok))
    }

    fn mk_metadata(name: &'static str) -> Arc<TokenColMetaData<'static>> {
        Arc::new(TokenColMetaData {
            columns: vec![MetaDataColumn {
                base: BaseMetaDataColumn {
                    user_type: 0,
                    flags: BitFlags::empty(),
                    ty: TypeInfo::FixedLen(FixedLenType::Int4),
                    table_name: None,
                },
                col_name: std::borrow::Cow::Borrowed(name),
            }],
        })
    }

    fn return_value_token(value: TokenReturnValue) -> ReceivedToken {
        ReceivedToken::ReturnValue(Box::new(value))
    }

    fn mk_return_value(name: &str, ordinal: u16, value: ColumnData<'static>) -> TokenReturnValue {
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
            value,
        }
    }

    #[test]
    fn matches_name_handles_at_prefix_and_case() {
        let ov: OutputValue = mk_return_value("@Handle", 0, ColumnData::I32(Some(7))).into();
        assert!(ov.matches_name("handle"));
        assert!(ov.matches_name("@handle"));
        assert!(ov.matches_name("HANDLE"));
        assert!(!ov.matches_name("cursor"));
    }

    #[test]
    fn matches_name_is_false_for_empty_server_name() {
        // SQL Server returns empty names for positional outputs; those must
        // not match arbitrary lookup keys.
        let ov: OutputValue = mk_return_value("", 0, ColumnData::I32(Some(7))).into();
        assert!(!ov.matches_name("handle"));
        assert!(!ov.matches_name(""));
    }

    #[test]
    fn matches_name_refuses_empty_query() {
        let ov: OutputValue = mk_return_value("@handle", 0, ColumnData::I32(Some(7))).into();
        assert!(!ov.matches_name(""));
        assert!(!ov.matches_name("@"));
    }

    #[test]
    fn get_decodes_i32_via_fromsql() {
        let ov: OutputValue = mk_return_value("@x", 1, ColumnData::I32(Some(42))).into();
        assert_eq!(ov.get::<i32>().unwrap(), Some(42));
    }

    #[test]
    fn get_returns_none_for_sql_null() {
        let ov: OutputValue = mk_return_value("@x", 1, ColumnData::I32(None)).into();
        assert_eq!(ov.get::<i32>().unwrap(), None);
    }

    #[test]
    fn get_errors_on_type_mismatch() {
        let ov: OutputValue =
            mk_return_value("@x", 1, ColumnData::String(Some("hello".into()))).into();
        let err = ov.get::<i32>().unwrap_err();
        assert!(matches!(err, crate::Error::Conversion(_)));
    }

    #[test]
    fn raw_accessor_exposes_column_data() {
        let ov: OutputValue = mk_return_value("@x", 1, ColumnData::I32(Some(42))).into();
        assert!(matches!(ov.raw(), ColumnData::I32(Some(42))));
    }

    #[test]
    fn metadata_accessors() {
        let ov: OutputValue = mk_return_value("@handle", 3, ColumnData::I32(Some(7))).into();
        assert_eq!(ov.name(), "@handle");
        assert_eq!(ov.ordinal(), 3);
    }

    #[tokio::test]
    async fn collect_drains_return_value_plus_status_plus_doneproc() {
        let s = synthetic(vec![
            return_value_token(mk_return_value("@handle", 1, ColumnData::I32(Some(42)))),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);
        let (outputs, status) = collect_rpc_outputs_from_stream(s).await.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].get::<i32>().unwrap(), Some(42));
        assert_eq!(status, Some(0));
    }

    #[tokio::test]
    async fn collect_captures_first_non_empty_metadata() {
        let s = synthetic(vec![
            ReceivedToken::NewResultset(Arc::new(TokenColMetaData {
                columns: Vec::new(),
            })),
            ReceivedToken::NewResultset(mk_metadata("v")),
            return_value_token(mk_return_value("@handle", 1, ColumnData::I32(Some(42)))),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);

        let (outputs, status, metadata) = collect_rpc_outputs_with_metadata_from_stream(s)
            .await
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].get::<i32>().unwrap(), Some(42));
        assert_eq!(status, Some(0));
        let metadata = metadata.unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].name(), "v");
        assert_eq!(
            metadata[0].type_info(),
            Some(&TypeInfo::FixedLen(FixedLenType::Int4))
        );
    }

    #[tokio::test]
    async fn collect_surfaces_first_token_error_after_draining() {
        let err = TokenError::new(50000, 1, 16, "test failure", "srv", "proc", 1);
        let s = synthetic(vec![
            ReceivedToken::Error(err),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);
        let result = collect_rpc_outputs_from_stream(s).await;
        match result {
            Err(crate::Error::Server(te)) => assert_eq!(te.code, 50000),
            other => panic!("expected Server error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn collect_keeps_first_error_across_multiple_error_tokens() {
        let first = TokenError::new(1, 1, 16, "first", "srv", "", 1);
        let second = TokenError::new(2, 1, 16, "second", "srv", "", 1);
        let s = synthetic(vec![
            ReceivedToken::Error(first),
            ReceivedToken::Error(second),
            mk_done_proc_final(),
        ]);
        match collect_rpc_outputs_from_stream(s).await {
            Err(crate::Error::Server(te)) => assert_eq!(te.code, 1),
            other => panic!("expected first error to win, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn collect_skips_done_proc_with_more_flag_and_terminates_on_final() {
        let s = synthetic(vec![
            return_value_token(mk_return_value("@a", 1, ColumnData::I32(Some(1)))),
            mk_done_proc_more(),
            return_value_token(mk_return_value("@b", 2, ColumnData::I32(Some(2)))),
            mk_done_proc_final(),
        ]);
        let (outputs, _) = collect_rpc_outputs_from_stream(s).await.unwrap();
        assert_eq!(outputs.len(), 2);
    }

    #[tokio::test]
    async fn collect_treats_bare_done_like_done_proc() {
        let s = synthetic(vec![
            return_value_token(mk_return_value("@a", 1, ColumnData::I32(Some(1)))),
            ReceivedToken::Done(TokenDone::with_rows(0)),
        ]);
        let (outputs, _) = collect_rpc_outputs_from_stream(s).await.unwrap();
        assert_eq!(outputs.len(), 1);
    }

    #[tokio::test]
    async fn collect_ignores_intermediate_done_in_proc() {
        // Servers sometimes emit DoneInProc even for "no-result" RPCs; it
        // must not terminate our drain loop.
        let s = synthetic(vec![
            ReceivedToken::DoneInProc(TokenDone::with_rows(0)),
            return_value_token(mk_return_value("@handle", 1, ColumnData::I32(Some(7)))),
            mk_done_proc_final(),
        ]);
        let (outputs, _) = collect_rpc_outputs_from_stream(s).await.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].get::<i32>().unwrap(), Some(7));
    }

    #[tokio::test]
    async fn collect_empty_stream_before_done_returns_empty() {
        // An empty stream (e.g. connection closed) should not panic; it
        // returns no outputs and no status.
        let s = synthetic(vec![mk_done_proc_final()]);
        let (outputs, status) = collect_rpc_outputs_from_stream(s).await.unwrap();
        assert!(outputs.is_empty());
        assert!(status.is_none());
    }

    fn mk_row(value: i32) -> ReceivedToken {
        let mut row = TokenRow::new();
        row.push(ColumnData::I32(Some(value)));
        ReceivedToken::Row(row)
    }

    #[tokio::test]
    async fn collect_result_sets_buffers_single_set_with_rows_and_outputs() {
        let s = synthetic(vec![
            ReceivedToken::NewResultset(mk_metadata("v")),
            mk_row(1),
            mk_row(2),
            mk_row(3),
            return_value_token(mk_return_value(
                "@prepared_handle",
                1,
                ColumnData::I32(Some(11)),
            )),
            return_value_token(mk_return_value("@cursor", 2, ColumnData::I32(Some(0)))),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);

        let (results, outputs, status, infos) =
            collect_rpc_result_sets_from_stream(s).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].columns.len(), 1);
        assert_eq!(results[0].columns[0].name(), "v");
        assert_eq!(results[0].rows.len(), 3);
        assert_eq!(results[0].rows[0].get::<i32, _>(0), Some(1));
        assert_eq!(results[0].rows[2].get::<i32, _>(0), Some(3));
        assert_eq!(results[0].rows[0].result_index(), 0);
        assert_eq!(outputs.len(), 2);
        assert_eq!(status, Some(0));
        assert!(infos.is_empty());
    }

    #[tokio::test]
    async fn collect_result_sets_preserves_multiple_sets_in_order() {
        let s = synthetic(vec![
            ReceivedToken::NewResultset(mk_metadata("v")),
            mk_row(1),
            mk_row(2),
            ReceivedToken::DoneInProc(TokenDone::with_rows(2)),
            ReceivedToken::NewResultset(mk_metadata("v")),
            mk_row(3),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);

        let (results, _outputs, _status, _infos) =
            collect_rpc_result_sets_from_stream(s).await.unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].rows.len(), 2);
        assert_eq!(results[0].rows[0].get::<i32, _>(0), Some(1));
        assert_eq!(results[0].rows[0].result_index(), 0);
        assert_eq!(results[1].rows.len(), 1);
        assert_eq!(results[1].rows[0].get::<i32, _>(0), Some(3));
        assert_eq!(results[1].rows[0].result_index(), 1);
    }

    #[tokio::test]
    async fn collect_result_sets_discards_rows_but_preserves_response_data() {
        let s = synthetic(vec![
            ReceivedToken::NewResultset(Arc::new(TokenColMetaData {
                columns: Vec::new(),
            })),
            ReceivedToken::NewResultset(mk_metadata("first")),
            mk_row(1),
            mk_row(2),
            ReceivedToken::DoneInProc(TokenDone::with_rows(2)),
            ReceivedToken::NewResultset(mk_metadata("second")),
            mk_row(3),
            ReceivedToken::Info(TokenInfo::new(
                5000,
                1,
                5,
                "procedure info",
                "srv",
                "proc",
                1,
            )),
            return_value_token(mk_return_value("@out", 1, ColumnData::I32(Some(11)))),
            ReceivedToken::ReturnStatus(7),
            mk_done_proc_final(),
        ]);

        let (results, outputs, status, infos) =
            collect_rpc_result_sets_from_stream_with_mode(s, RowCollectionMode::DiscardRows)
                .await
                .unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].columns[0].name(), "first");
        assert_eq!(results[1].columns[0].name(), "second");
        assert!(results.iter().all(|result| result.rows.is_empty()));
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].get::<i32>().unwrap(), Some(11));
        assert_eq!(status, Some(7));
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].number, 5000);
    }

    #[tokio::test]
    async fn collect_result_sets_drops_empty_colmetadata_placeholder() {
        let s = synthetic(vec![
            ReceivedToken::NewResultset(Arc::new(TokenColMetaData {
                columns: Vec::new(),
            })),
            ReceivedToken::NewResultset(mk_metadata("v")),
            mk_row(1),
            mk_done_proc_final(),
        ]);

        let (results, _outputs, _status, _infos) =
            collect_rpc_result_sets_from_stream(s).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rows[0].get::<i32, _>(0), Some(1));
        assert_eq!(results[0].rows[0].result_index(), 0);
    }

    #[tokio::test]
    async fn collect_result_sets_surfaces_first_error() {
        let err = TokenError::new(50000, 1, 16, "boom", "srv", "proc", 1);
        let s = synthetic(vec![
            ReceivedToken::NewResultset(mk_metadata("v")),
            mk_row(1),
            ReceivedToken::Error(err),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);

        match collect_rpc_result_sets_from_stream(s).await {
            Err(crate::Error::Server(te)) => assert_eq!(te.code, 50000),
            other => panic!("expected Server error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn collect_result_sets_discard_mode_surfaces_error_after_rows() {
        let err = TokenError::new(50000, 1, 16, "boom", "srv", "proc", 1);
        let s = synthetic(vec![
            ReceivedToken::NewResultset(mk_metadata("v")),
            mk_row(1),
            ReceivedToken::Error(err),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);

        match collect_rpc_result_sets_from_stream_with_mode(s, RowCollectionMode::DiscardRows).await
        {
            Err(crate::Error::Server(te)) => assert_eq!(te.code, 50000),
            other => panic!("expected Server error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn collect_result_sets_surfaces_attention_as_canceled() {
        let s = synthetic(vec![ReceivedToken::DoneProc(TokenDone::with_status(
            DoneStatus::Attention.into(),
            0,
        ))]);

        let result = collect_rpc_result_sets_from_stream(s).await;

        assert!(matches!(result, Err(crate::Error::Canceled)));
    }

    #[tokio::test]
    async fn collect_result_sets_no_result_sets_outputs_only() {
        // The normal (non-AllowDirect) shape: no inline rows, just outputs.
        let s = synthetic(vec![
            return_value_token(mk_return_value("@handle", 1, ColumnData::I32(Some(7)))),
            ReceivedToken::ReturnStatus(0),
            mk_done_proc_final(),
        ]);

        let (results, outputs, status, infos) =
            collect_rpc_result_sets_from_stream(s).await.unwrap();

        assert!(results.is_empty());
        assert_eq!(outputs.len(), 1);
        assert_eq!(status, Some(0));
        assert!(infos.is_empty());
    }

    #[tokio::test]
    async fn collect_result_sets_retains_info_tokens() {
        let s = synthetic(vec![
            ReceivedToken::Info(TokenInfo::new(
                16954,
                1,
                10,
                "Executing SQL directly; no cursor.",
                "srv",
                "",
                1,
            )),
            return_value_token(mk_return_value("", 1, ColumnData::I32(Some(11)))),
            mk_done_proc_final(),
        ]);

        let (_results, outputs, _status, infos) =
            collect_rpc_result_sets_from_stream(s).await.unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].number, 16954);
    }

    fn batch_codes(results: Vec<crate::Result<()>>) -> Vec<Option<u32>> {
        results
            .into_iter()
            .map(|result| match result {
                Ok(()) => None,
                Err(crate::Error::Server(error)) => Some(error.code),
                Err(_) => Some(0),
            })
            .collect()
    }

    #[tokio::test]
    async fn batch_results_attribute_each_error_to_its_own_call() {
        let error = |code| ReceivedToken::Error(TokenError::new(code, 1, 16, "e", "srv", "", 1));
        let cases = vec![
            (
                vec![mk_done_proc_more(), mk_done_proc_final()],
                vec![None, None],
            ),
            (
                vec![
                    error(16945),
                    mk_done_proc_more(),
                    ReceivedToken::ReturnStatus(0),
                    mk_done_proc_final(),
                ],
                vec![Some(16945), None],
            ),
            (
                vec![
                    mk_done_proc_more(),
                    error(8179),
                    error(1),
                    mk_done_proc_final(),
                ],
                vec![None, Some(8179)],
            ),
            // A batch whose intermediate DONEPROC lacks `More` is still read to
            // the end of the expected calls.
            (
                vec![mk_done_proc_final(), mk_done_proc_final()],
                vec![None, None],
            ),
        ];
        for (tokens, expected) in cases {
            let results = collect_rpc_batch_results_from_stream(synthetic(tokens), 2)
                .await
                .unwrap();
            assert_eq!(batch_codes(results), expected);
        }
    }

    #[tokio::test]
    async fn batch_results_fail_calls_missing_from_a_short_response() {
        let results =
            collect_rpc_batch_results_from_stream(synthetic(vec![mk_done_proc_final()]), 2)
                .await
                .unwrap();
        assert_eq!(batch_codes(results), vec![None, Some(0)]);

        let rejected = synthetic(vec![
            ReceivedToken::Error(TokenError::new(102, 1, 15, "syntax", "srv", "", 1)),
            ReceivedToken::Done(TokenDone::with_rows(0)),
        ]);
        let results = collect_rpc_batch_results_from_stream(rejected, 2)
            .await
            .unwrap();
        assert_eq!(batch_codes(results), vec![Some(102), Some(0)]);
    }
}
