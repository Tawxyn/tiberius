//! Client-side prepared statement handles.
//!
//! Server-assigned handles returned by `sp_prepare` / `sp_prepexec`. Use
//! [`Client::prepare`](crate::Client::prepare) to obtain a statement and
//! [`PreparedStatement::query`] / [`PreparedStatement::execute`] to run it
//! with different parameter values.
//!
//! When dropped without an explicit [`PreparedStatement::unprepare`] call,
//! the server-side handle leaks until the connection closes (the server's
//! procedure cache reaps it then). A warning is emitted via `tracing` so
//! leaks are visible in logs.

use std::borrow::Cow;

use enumflags2::BitFlags;
use futures_util::io::{AsyncRead, AsyncWrite};
use tracing::{event, Level};

use crate::client::rpc_response::{collect_rpc_outputs, OutputValue};
use crate::result::ExecuteResult;
use crate::tds::codec::{ColumnData, RpcParam, RpcProcId, RpcStatus};
use crate::tds::stream::{QueryStream, TokenStream};
use crate::{Client, ToSql};

/// An opaque handle identifying a prepared statement on the server.
///
/// Wraps the raw `i32` that TDS ships on the wire so the value can't be
/// confused with other handle-shaped integers. Must be passed back to the
/// same connection it was created on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PreparedHandle(i32);

impl PreparedHandle {
    pub(crate) fn from_i32(value: i32) -> Self {
        Self(value)
    }

    /// Raw wire value. Mainly useful for logging; pass the typed
    /// [`PreparedHandle`] around instead of the `i32` whenever possible.
    pub fn as_i32(self) -> i32 {
        self.0
    }
}

impl From<PreparedHandle> for i32 {
    fn from(h: PreparedHandle) -> Self {
        h.0
    }
}

/// A handle to a statement that has been prepared on the server.
///
/// Use [`query`](Self::query) / [`execute`](Self::execute) to re-execute the
/// statement with different parameter values. Call
/// [`unprepare`](Self::unprepare) when you are done, or allow the
/// connection to close — the server reaps handles on disconnect.
///
/// **Caveat:** a `PreparedStatement` is only valid for the [`Client`] it was
/// obtained from. Passing it to a different client — including a reconnect
/// of the same logical connection — will hit the server's procedure cache
/// with an unknown handle and fail. The API does not enforce this at
/// compile time.
#[derive(Debug)]
pub struct PreparedStatement {
    handle: PreparedHandle,
    sql: String,
    param_defs: String,
    /// `true` once the `sp_unprepare` packet has reached the wire. Set
    /// before the response is drained so that cancellation / I/O hiccups
    /// during the drain don't emit a spurious drop-warning.
    released: bool,
}

impl PreparedStatement {
    pub(crate) fn new(handle: PreparedHandle, sql: String, param_defs: String) -> Self {
        Self {
            handle,
            sql,
            param_defs,
            released: false,
        }
    }

    /// The server-assigned handle.
    pub fn handle(&self) -> PreparedHandle {
        self.handle
    }

    /// The SQL text that was prepared.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// The parameter definitions string supplied at prepare time — the
    /// verbatim T-SQL declaration (e.g. `"@P1 int, @P2 nvarchar(50)"`).
    /// Parameter names passed at execute time must match these declarations.
    pub fn param_defs(&self) -> &str {
        &self.param_defs
    }

    /// Execute the prepared statement with the given parameter values and
    /// return the affected row counts.
    pub async fn execute<'a, S>(
        &self,
        client: &'a mut Client<S>,
        params: &[&dyn ToSql],
    ) -> crate::Result<ExecuteResult>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let rpc_params = build_execute_params(self.handle, params);
        client.send_rpc(RpcProcId::Execute, rpc_params).await?;
        ExecuteResult::new(&mut client.connection).await
    }

    /// Execute the prepared statement with the given parameter values and
    /// return a streaming result set.
    pub async fn query<'a, S>(
        &self,
        client: &'a mut Client<S>,
        params: &[&dyn ToSql],
    ) -> crate::Result<QueryStream<'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let rpc_params = build_execute_params(self.handle, params);
        client.send_rpc(RpcProcId::Execute, rpc_params).await?;

        let ts = TokenStream::new(&mut client.connection);
        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;
        Ok(result)
    }

    /// Release the server-side handle and consume this statement.
    ///
    /// The statement is flagged released as soon as the `sp_unprepare`
    /// packet reaches the wire, so an error surfaced while draining the
    /// response (cancellation, network glitch, etc.) does not trigger a
    /// spurious drop-time warning — the handle is gone from the server's
    /// perspective regardless.
    pub async fn unprepare<S>(mut self, client: &mut Client<S>) -> crate::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.release(client).await
    }

    /// Executes the statement a last time and then releases it, as
    /// [`execute`](Self::execute) followed by [`unprepare`](Self::unprepare)
    /// would. Returns the row counts reported before the execution's first
    /// error, with that error.
    ///
    /// The release is attempted even when the execution fails or is
    /// canceled, as long as the connection can still carry a request. When
    /// both fail, the error is [`CleanupFailed`](crate::error::Error::CleanupFailed),
    /// which keeps the execution's error and its code. An execution error
    /// that leaves the connection unusable, such as an I/O or protocol error,
    /// is returned without attempting the release. Whenever the error's
    /// [`leaves_connection_usable`](crate::error::Error::leaves_connection_usable)
    /// is `false`, the connection should be discarded, which frees the
    /// handle.
    pub async fn execute_and_unprepare<S>(
        mut self,
        client: &mut Client<S>,
        params: &[&dyn ToSql],
    ) -> (ExecuteResult, Option<crate::Error>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // The release is not sent in the execution's request: an attention
        // aborts the whole request it interrupts, so a release that had not
        // yet run would be lost along with this consumed statement.
        let (result, error) = self.execute_until_error(client, params).await;
        if error
            .as_ref()
            .is_some_and(|error| !error.leaves_connection_usable())
        {
            return (result, error);
        }
        let released = self.release(client).await;
        (result, crate::Error::with_cleanup(error, released))
    }

    async fn execute_until_error<S>(
        &self,
        client: &mut Client<S>,
        params: &[&dyn ToSql],
    ) -> (ExecuteResult, Option<crate::Error>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Err(error) = client.connection.flush_stream().await {
            return (ExecuteResult::empty(), Some(error));
        }
        let rpc_params = build_execute_params(self.handle, params);
        if let Err(error) = client.send_rpc(RpcProcId::Execute, rpc_params).await {
            return (ExecuteResult::empty(), Some(error));
        }
        ExecuteResult::until_error(&mut client.connection).await
    }

    async fn release<S>(&mut self, client: &mut Client<S>) -> crate::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let handle_param = RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(self.handle.as_i32())),
        };
        client
            .send_rpc(RpcProcId::Unprepare, vec![handle_param])
            .await?;
        // From the server's standpoint the handle is released the moment
        // the RPC is processed; anything we discover while draining is
        // informational only.
        self.released = true;
        collect_rpc_outputs(&mut client.connection).await?;
        Ok(())
    }
}

impl Drop for PreparedStatement {
    fn drop(&mut self) {
        if !self.released {
            event!(
                Level::WARN,
                handle = self.handle.as_i32(),
                "PreparedStatement dropped without unprepare; server-side handle will leak until the connection closes"
            );
        }
    }
}

/// Build the RPC parameter list for `sp_execute`: `[@handle, @P1, @P2, ...]`.
fn build_execute_params<'a>(
    handle: PreparedHandle,
    params: &[&'a dyn ToSql],
) -> Vec<RpcParam<'a>> {
    let mut rpc_params: Vec<RpcParam<'a>> = Vec::with_capacity(params.len() + 1);
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: BitFlags::empty(),
        type_info: None,
        value: ColumnData::I32(Some(handle.as_i32())),
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

/// Build the RPC parameter list for `sp_prepare`:
/// `[@handle OUT int, @params nvarchar, @stmt nvarchar, @options int]`.
pub(crate) fn build_prepare_params<'a>(
    sql: Cow<'a, str>,
    param_defs: Cow<'a, str>,
) -> Vec<RpcParam<'a>> {
    // SQL Server identifies these parameters positionally; the names are
    // conventionally empty on the wire. `ColumnData::I32(Some(0))` self-
    // describes as `VarLenType::Intn(4)` so the server can echo the real
    // handle back with known-int type info.
    vec![
        RpcParam {
            name: Cow::Borrowed(""),
            flags: RpcStatus::ByRefValue.into(),
            type_info: None,
            value: ColumnData::I32(Some(0)),
        },
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::String(Some(param_defs)),
        },
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::String(Some(sql)),
        },
        RpcParam {
            name: Cow::Borrowed(""),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(Some(1)),
        },
    ]
}

/// Build the RPC parameter list for `sp_prepexec`:
/// `[@handle OUT int, @params nvarchar, @stmt nvarchar, @P1, @P2, ...]`.
pub(crate) fn build_prepexec_params<'a>(
    sql: Cow<'a, str>,
    param_defs: Cow<'a, str>,
    params: &[&'a dyn ToSql],
) -> Vec<RpcParam<'a>> {
    let mut rpc_params: Vec<RpcParam<'a>> = Vec::with_capacity(params.len() + 3);
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
        value: ColumnData::String(Some(param_defs)),
    });
    rpc_params.push(RpcParam {
        name: Cow::Borrowed(""),
        flags: BitFlags::empty(),
        type_info: None,
        value: ColumnData::String(Some(sql)),
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

/// Extract the `@handle` output parameter from the drained output list.
///
/// Real SQL Server emits the handle as an unnamed positional output, while
/// the Tiberius self-hosted test harness uses a named `@handle`. We match
/// by name first, then fall back to the first output.
///
/// A returned handle of `0` is treated as a server-side failure rather than
/// a valid handle — `sp_prepare` / `sp_prepexec` never allocate handle `0`,
/// so seeing it means the server skipped its own error path.
pub(crate) fn extract_handle(outputs: &[OutputValue]) -> crate::Result<PreparedHandle> {
    let handle_ov = outputs
        .iter()
        .find(|o| o.matches_name("handle"))
        .or_else(|| outputs.first())
        .ok_or_else(|| {
            crate::Error::Protocol(
                "prepare: server did not return a @handle output parameter".into(),
            )
        })?;
    let handle = handle_ov.get::<i32>()?.ok_or_else(|| {
        crate::Error::Protocol("prepare: @handle output parameter is NULL".into())
    })?;
    if handle == 0 {
        return Err(crate::Error::Protocol(
            "prepare: server returned a zero @handle (internal failure)".into(),
        ));
    }
    Ok(PreparedHandle(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_handle_round_trip() {
        let h = PreparedHandle(0x1234_5678);
        assert_eq!(h.as_i32(), 0x1234_5678);
        assert_eq!(i32::from(h), 0x1234_5678);
    }
}
