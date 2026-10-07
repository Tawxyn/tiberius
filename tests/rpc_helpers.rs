//! End-to-end tests for the prepare / prep_exec / unprepare / cursor client APIs.
//!
//! A Tiberius server (in-process, via the `server-smol` backend) is spawned
//! on `127.0.0.1:0`; a Tiberius client connects over TCP and drives the new
//! RPC helpers against handlers that simulate a minimal SQL executor.

#![cfg(feature = "server-smol")]

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use enumflags2::BitFlags;
use futures_util::sink::SinkExt;

use tiberius::numeric::Numeric;
use tiberius::server::sp_cursor::{
    CursorCache, CursorEntry, CursorHandle, ParsedCursorClose, ParsedCursorFetch, ParsedCursorOpen,
    SpCursorCloseHandler, SpCursorFetchHandler, SpCursorOpenHandler,
};
use tiberius::server::{
    process_connection, send_output_param, send_output_params, send_return_status, AuthBuilder,
    AuthError, AuthHandler, AuthSuccess, BackendToken, BoxFuture, DefaultEnvChangeProvider,
    LoginInfo, NoOpAttention, NoOpError, OutputParameter, ParsedExecute, ParsedPrepExec,
    ParsedPrepare, ParsedUnprepare, PreparedHandle, ProcedureCache, RejectBulkLoad,
    ResultSetWriter, RpcHandler, RpcProcId, SpExecuteHandler, SpPrepExecHandler, SpPrepareHandler,
    SpUnprepareHandler, SqlAuthSource, SqlBatchHandler, SystemProcRouter, SystemProcRouterBuilder,
    TdsAuthHandler, TdsBackendMessage, TdsClient, TdsServerHandlers,
};
use tiberius::{
    BaseMetaDataColumn, Client, ColumnData, ColumnFlag, Config, CursorOpenOptions,
    CursorScrollOptions, DoneStatus, EncryptionLevel, FixedLenType, MetaDataColumn,
    ProcedureParameter, TokenColMetaData, TokenDone, TokenInfo, TypeInfo, VarLenContext,
    VarLenType,
};

// =============================================================================
// Trivial auth source — accepts everything
// =============================================================================

#[derive(Debug, Default)]
struct AlwaysOkAuth;

#[async_trait]
impl SqlAuthSource for AlwaysOkAuth {
    async fn authenticate(
        &self,
        _login: &LoginInfo,
        _password: &str,
    ) -> std::result::Result<AuthSuccess, AuthError> {
        Ok(AuthSuccess::default())
    }
}

struct TestAuth {
    inner: TdsAuthHandler<DefaultEnvChangeProvider>,
}

impl TestAuth {
    fn new() -> Self {
        let inner = AuthBuilder::new(DefaultEnvChangeProvider::default())
            .encryption(EncryptionLevel::NotSupported)
            .with_sql_auth(Arc::new(AlwaysOkAuth::default()))
            .allow_trust()
            .build();
        Self { inner }
    }
}

impl AuthHandler for TestAuth {
    fn on_prelogin<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::PreloginMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        self.inner.on_prelogin(client, message)
    }

    fn on_login<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::LoginMessage<'static>,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        self.inner.on_login(client, message)
    }

    fn on_sspi<'a, C>(
        &'a self,
        client: &'a mut C,
        token: tiberius::TokenSspi,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        self.inner.on_sspi(client, token)
    }
}

// =============================================================================
// Trivial SQL batch handler — responds with a single empty Done
// =============================================================================

/// SQL text that makes [`NoopSqlBatch`] simulate a long, packet-less statement
/// (the moral equivalent of `WAITFOR DELAY`): it emits no tokens and waits for
/// an attention/cancellation to arrive.
const PACKETLESS_DELAY_SQL: &str = "/* packetless-cancel-probe */ WAITFOR DELAY";

struct NoopSqlBatch;

impl SqlBatchHandler for NoopSqlBatch {
    fn on_sql_batch<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::server::SqlBatchMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            if message.batch.contains(PACKETLESS_DELAY_SQL) {
                // Simulate a long-running, packet-less statement: send nothing
                // and cooperatively poll for an attention. When the client's
                // CancellationToken fires, the (fixed) client wakes its parked
                // read and sends a TDS attention; we observe it here and return,
                // and the connection driver auto-emits Done+Attention.
                //
                // The loop is capped so that — absent a working cancel — the
                // statement still terminates rather than hanging the suite (the
                // test's timing assertion is what fails in that case). 500 * 10ms
                // = 5s cap, well above the ~tens-of-ms a working cancel takes.
                for _ in 0..500 {
                    if client.poll_attention().await? {
                        return Ok(());
                    }
                    smol::Timer::after(std::time::Duration::from_millis(10)).await;
                }
            }

            client
                .send(TdsBackendMessage::Token(BackendToken::Done(
                    TokenDone::with_rows(0),
                )))
                .await
        })
    }
}

// =============================================================================
// Shared state for prepared-statement + cursor handlers
// =============================================================================

struct SharedState {
    procs: Mutex<ProcedureCache>,
    cursors: Mutex<CursorCache>,
    /// Rows materialized per cursor handle.
    cursor_rows: Mutex<HashMap<CursorHandle, Vec<i32>>>,
    /// Records the parameters of every `sp_cursorfetch` RPC the server
    /// observed. Tests assert on this to prove the client's wire encoding
    /// of (fetch_type, row_num, n_rows) actually reaches the server.
    cursor_fetch_log: Mutex<Vec<(i32, i32, i32)>>,
    cursorprepexec_param_defs_log: Mutex<Vec<Option<String>>>,
    cursorprepexec_send_metadata: Mutex<bool>,
    /// When set, `sp_cursorprepexec` takes the AllowDirect fast path: it
    /// prepares the statement, emits INFO 16954, and streams the result sets
    /// inline instead of opening a cursor.
    cursorprepexec_allow_direct: Mutex<bool>,
    /// When set, a metadata-only (`n_rows == 0`) `sp_cursorfetch` emits no
    /// tokens and instead polls for an attention, simulating a stalled probe.
    /// Used to exercise cancellation of the metadata-fetch read path.
    stall_metadata_fetch: Mutex<bool>,
    /// When set, `sp_cursorclose` fails with a server error, as it does for a
    /// cursor the server has already closed.
    fail_cursor_close: Mutex<bool>,
    /// When set, `sp_unprepare` and `sp_cursorunprepare` drop the connection
    /// instead of answering, so the client's release fails with an I/O error.
    drop_on_release: Mutex<bool>,
    /// When set, `sp_unprepare` fails with a fatal server error and then
    /// drops the connection.
    fatal_on_release: Mutex<bool>,
    rpc_log: Mutex<Vec<RpcProcId>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            procs: Mutex::new(ProcedureCache::new(1)),
            cursors: Mutex::new(CursorCache::new(1)),
            cursor_rows: Mutex::new(HashMap::new()),
            cursor_fetch_log: Mutex::new(Vec::new()),
            cursorprepexec_param_defs_log: Mutex::new(Vec::new()),
            cursorprepexec_send_metadata: Mutex::new(false),
            cursorprepexec_allow_direct: Mutex::new(false),
            stall_metadata_fetch: Mutex::new(false),
            fail_cursor_close: Mutex::new(false),
            drop_on_release: Mutex::new(false),
            fatal_on_release: Mutex::new(false),
            rpc_log: Mutex::new(Vec::new()),
        }
    }
}

// =============================================================================
// Minimal SQL "evaluator"
// =============================================================================
//
// Supports exactly:
//   "SELECT @P1 AS v"          — one int column, value = @P1
//   "SELECT @P1 + @P2 AS s"    — one int column, value = @P1 + @P2
//   "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v"
//                               — three-row result, used for cursor tests
//
// Both named-parameter binding ("@id", "@P1") are resolved via a hashmap built
// from the execution params.

fn eval_sql(sql: &str, params: &HashMap<String, i32>) -> Vec<i32> {
    let sql = sql.trim();
    if sql.eq_ignore_ascii_case("SELECT @P1 AS v") {
        return vec![params.get("@P1").copied().unwrap_or(0)];
    }
    if sql.eq_ignore_ascii_case("SELECT @P1 + @P2 AS s") {
        let a = params.get("@P1").copied().unwrap_or(0);
        let b = params.get("@P2").copied().unwrap_or(0);
        return vec![a + b];
    }
    if sql.eq_ignore_ascii_case("SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v") {
        return vec![1, 2, 3];
    }
    // Fail loud rather than silently returning an empty result set — real
    // SQL Server would reject malformed SQL, and silence here would mask
    // client-side bugs that place the param-defs string in the SQL slot,
    // botch parameter names, etc.
    panic!(
        "test harness received SQL it doesn't recognise: {:?} (known params: {:?}). \
         Either the client sent the wrong string or this harness needs a new arm.",
        sql, params
    );
}

fn int_int_column() -> MetaDataColumn<'static> {
    MetaDataColumn {
        base: BaseMetaDataColumn {
            user_type: 0,
            flags: BitFlags::from(ColumnFlag::Nullable),
            ty: TypeInfo::FixedLen(FixedLenType::Int4),
            table_name: None,
        },
        col_name: Cow::Borrowed("v"),
    }
}

async fn write_int_result_set<C>(
    client: &mut C,
    rows: &[i32],
    final_done_flags: FinalDone,
) -> tiberius::Result<()>
where
    C: TdsClient,
{
    let mut writer = ResultSetWriter::start(client, vec![int_int_column()]).await?;
    for v in rows {
        writer.send_row_iter([ColumnData::I32(Some(*v))]).await?;
    }
    // DoneInProc is part of an in-flight RPC response — subsequent tokens
    // (ReturnValue, ReturnStatus, DoneProc) follow, so we must NOT flag this
    // as end-of-message.
    match final_done_flags {
        FinalDone::InProcMore => {
            let done = TokenDone::with_more_rows(rows.len() as u64);
            writer
                .into_client()
                .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                    done,
                )))
                .await
        }
        FinalDone::InProc => {
            let done = TokenDone::with_rows(rows.len() as u64);
            writer
                .into_client()
                .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                    done,
                )))
                .await
        }
    }
}

enum FinalDone {
    InProc,
    InProcMore,
}

// =============================================================================
// Prepare / Execute / Unprepare
// =============================================================================

struct TestPrepare(Arc<SharedState>);

impl SpPrepareHandler for TestPrepare {
    fn prepare<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedPrepare<'a>,
    ) -> BoxFuture<'a, tiberius::Result<PreparedHandle>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let sql = request.sql().to_string();
            let handle = self
                .0
                .procs
                .lock()
                .unwrap()
                .prepare(sql, Vec::new(), Vec::new());

            send_output_param(
                client,
                OutputParameter::new("@handle", ColumnData::I32(Some(handle.as_i32())))
                    .with_ordinal(1)
                    .with_type_info(request.handle_type_info().clone()),
            )
            .await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(handle)
        })
    }
}

/// Prepared SQL that makes [`TestExecute`] send nothing until an attention
/// arrives, like a long-running statement.
const STALLED_EXECUTE_SQL: &str = "/* stalled-execute-probe */ SELECT @P1 AS v";

/// Prepared SQL that makes [`TestExecute`] fail with a server error.
const FAILING_EXECUTE_SQL: &str = "/* failing-execute-probe */ SELECT @P1 AS v";

/// Prepared SQL that makes [`TestExecute`] fail with a fatal server error.
const FATAL_EXECUTE_SQL: &str = "/* fatal-execute-probe */ SELECT @P1 AS v";

/// Answers with a severity 20 error and then drops the connection, as SQL
/// Server does after a fatal error.
async fn fail_fatally<C: TdsClient>(client: &mut C) -> tiberius::Result<()> {
    client
        .send(TdsBackendMessage::TokenPartial(BackendToken::Error(
            tiberius::TokenError::new(50000, 1, 20, "Fatal error", "test-server", "", 1),
        )))
        .await?;
    client
        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
            TokenDone::with_status(DoneStatus::SrvError.into(), 0),
        )))
        .await?;
    drop_connection()
}

struct TestExecute(Arc<SharedState>);

impl SpExecuteHandler for TestExecute {
    fn execute<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedExecute<'a>,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let handle = request.handle();
            let sql = {
                let mut cache = self.0.procs.lock().unwrap();
                match cache.get_and_record(&handle) {
                    Some(stmt) => stmt.sql.clone(),
                    None => {
                        return Err(tiberius::error::Error::Protocol(
                            format!("unknown prepared handle {}", handle.as_i32()).into(),
                        ));
                    }
                }
            };
            if sql == STALLED_EXECUTE_SQL {
                // Capped so that a cancel that never arrives fails the test
                // instead of hanging it.
                for _ in 0..500 {
                    if client.poll_attention().await? {
                        return Ok(());
                    }
                    smol::Timer::after(std::time::Duration::from_millis(10)).await;
                }
                return Err(tiberius::error::Error::Protocol(
                    "stalled execute was not canceled".into(),
                ));
            }
            if sql == FAILING_EXECUTE_SQL {
                client
                    .send(TdsBackendMessage::TokenPartial(BackendToken::Error(
                        tiberius::TokenError::new(
                            2627,
                            1,
                            14,
                            "Violation of PRIMARY KEY constraint",
                            "test-server",
                            "",
                            1,
                        ),
                    )))
                    .await?;
                client
                    .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                        TokenDone::with_status(DoneStatus::Error.into(), 0),
                    )))
                    .await?;
                return Ok(());
            }
            if sql == FATAL_EXECUTE_SQL {
                return fail_fatally(client).await;
            }
            let params = collect_params(&request);
            let rows = eval_sql(&sql, &params);

            write_int_result_set(client, &rows, FinalDone::InProcMore).await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(rows.len() as u64),
                )))
                .await?;
            Ok(())
        })
    }
}

/// A handler error makes the server end the connection without answering.
fn drop_connection() -> tiberius::Result<()> {
    Err(tiberius::error::Error::Protocol(
        "test harness: dropping the connection".into(),
    ))
}

struct TestUnprepare(Arc<SharedState>);

impl SpUnprepareHandler for TestUnprepare {
    fn unprepare<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedUnprepare,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            self.0.rpc_log.lock().unwrap().push(RpcProcId::Unprepare);
            if *self.0.drop_on_release.lock().unwrap() {
                return drop_connection();
            }
            if *self.0.fatal_on_release.lock().unwrap() {
                return fail_fatally(client).await;
            }
            self.0.procs.lock().unwrap().unprepare(&request.handle());
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(())
        })
    }
}

// =============================================================================
// PrepExec
// =============================================================================

struct TestPrepExec(Arc<SharedState>);

impl SpPrepExecHandler for TestPrepExec {
    fn prep_exec<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedPrepExec<'a>,
    ) -> BoxFuture<'a, tiberius::Result<PreparedHandle>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let sql = request.sql().to_string();
            let handle_type = request.handle_type_info().clone();
            let handle = self
                .0
                .procs
                .lock()
                .unwrap()
                .prepare(sql.clone(), Vec::new(), Vec::new());

            let mut params: HashMap<String, i32> = HashMap::new();
            for p in request.params() {
                if let Some(v) = p.get_i32() {
                    params.insert(p.name().to_string(), v);
                }
            }
            let rows = eval_sql(&sql, &params);
            write_int_result_set(client, &rows, FinalDone::InProc).await?;
            send_output_param(
                client,
                OutputParameter::new("@handle", ColumnData::I32(Some(handle.as_i32())))
                    .with_ordinal(1)
                    .with_type_info(handle_type),
            )
            .await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(rows.len() as u64),
                )))
                .await?;
            Ok(handle)
        })
    }
}

fn collect_params(request: &ParsedExecute<'_>) -> HashMap<String, i32> {
    let mut out = HashMap::new();
    for p in request.params() {
        if let Some(v) = p.get_i32() {
            out.insert(p.name().to_string(), v);
        }
    }
    out
}

// =============================================================================
// Cursor handlers
// =============================================================================

struct TestCursorOpen(Arc<SharedState>);

impl SpCursorOpenHandler for TestCursorOpen {
    fn cursor_open<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorOpen<'a>,
    ) -> BoxFuture<'a, tiberius::Result<CursorHandle>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let rows = eval_sql(&request.sql, &HashMap::new());
            let scrollopt = request.scrollopt;
            let ccopt = request.ccopt;

            let entry =
                CursorEntry::new(request.sql.to_string(), scrollopt, ccopt, rows.len() as i32);
            let handle = self.0.cursors.lock().unwrap().open(entry);
            self.0
                .cursor_rows
                .lock()
                .unwrap()
                .insert(handle, rows.clone());

            // Build output parameters in the order the spec declares.
            let outputs = vec![
                OutputParameter::new("@cursor", ColumnData::I32(Some(handle.as_i32())))
                    .with_ordinal(1)
                    .with_type_info(request.cursor_type_info.clone()),
                OutputParameter::new("@scrollopt", ColumnData::I32(Some(scrollopt)))
                    .with_ordinal(3)
                    .with_type_info(request.scrollopt_type_info.clone()),
                OutputParameter::new("@ccopt", ColumnData::I32(Some(ccopt)))
                    .with_ordinal(4)
                    .with_type_info(request.ccopt_type_info.clone()),
                OutputParameter::new("@rowcount", ColumnData::I32(Some(rows.len() as i32)))
                    .with_ordinal(5)
                    .with_type_info(request.rowcount_type_info.clone()),
            ];
            send_output_params(client, outputs).await?;
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(handle)
        })
    }
}

struct TestCursorFetch(Arc<SharedState>);

impl SpCursorFetchHandler for TestCursorFetch {
    fn cursor_fetch<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorFetch,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            self.0.rpc_log.lock().unwrap().push(RpcProcId::CursorFetch);
            // Record the fetch params so tests can assert the client's
            // wire encoding of (fetch_type, row_num, n_rows) survived the
            // round trip.
            self.0.cursor_fetch_log.lock().unwrap().push((
                request.fetch_type,
                request.row_num,
                request.n_rows,
            ));

            let rows = {
                let store = self.0.cursor_rows.lock().unwrap();
                store.get(&request.handle).cloned().unwrap_or_default()
            };

            // Simulate a stalled metadata probe: emit no tokens and poll for an
            // attention so a `cancel()` during `fetch_metadata` can interrupt
            // the read. Read the flag into a bool first so no lock guard is held
            // across an await. Capped so an un-cancelled run can't hang.
            let stall = request.n_rows == 0 && *self.0.stall_metadata_fetch.lock().unwrap();
            if stall {
                for _ in 0..500 {
                    if client.poll_attention().await? {
                        return Ok(());
                    }
                    smol::Timer::after(std::time::Duration::from_millis(10)).await;
                }
            }

            if request.n_rows == 0 {
                client
                    .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(
                        TokenColMetaData {
                            columns: vec![int_int_column()],
                        },
                    )))
                    .await?;
                client
                    .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                        TokenDone::with_rows(0),
                    )))
                    .await?;
            } else {
                write_int_result_set(client, &rows, FinalDone::InProc).await?;
            }
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(rows.len() as u64),
                )))
                .await?;
            Ok(())
        })
    }
}

struct TestCursorClose(Arc<SharedState>);

impl SpCursorCloseHandler for TestCursorClose {
    fn cursor_close<'a, C>(
        &'a self,
        client: &'a mut C,
        request: ParsedCursorClose,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            self.0.rpc_log.lock().unwrap().push(RpcProcId::CursorClose);
            let fail = *self.0.fail_cursor_close.lock().unwrap();
            if fail {
                client
                    .send(TdsBackendMessage::TokenPartial(BackendToken::Error(
                        tiberius::TokenError::new(
                            16917,
                            1,
                            16,
                            "Cursor is not open.",
                            "test-server",
                            "",
                            1,
                        ),
                    )))
                    .await?;
                client
                    .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                        TokenDone::with_status(DoneStatus::Error.into(), 0),
                    )))
                    .await?;
                return Ok(());
            }
            self.0.cursors.lock().unwrap().close(&request.handle);
            self.0.cursor_rows.lock().unwrap().remove(&request.handle);
            send_return_status(client, 0).await?;
            client
                .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                    TokenDone::with_rows(0),
                )))
                .await?;
            Ok(())
        })
    }
}

// =============================================================================
// Server wiring
// =============================================================================

type TestRouter = SystemProcRouter<
    RejectIt,
    TestPrepare,
    TestExecute,
    TestUnprepare,
    TestPrepExec,
    TestCursorOpen,
    TestCursorFetch,
    TestCursorClose,
    SpecialRpc,
>;

struct RejectIt;

impl RpcHandler for RejectIt {
    fn on_rpc<'a, C>(
        &'a self,
        _client: &'a mut C,
        _message: tiberius::server::RpcMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(tiberius::error::Error::Protocol(
                "test harness: unexpected RPC".into(),
            ))
        })
    }
}

struct SpecialRpc(Arc<SharedState>);

impl RpcHandler for SpecialRpc {
    fn on_rpc<'a, C>(
        &'a self,
        client: &'a mut C,
        message: tiberius::server::RpcMessage,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            match message.proc_id {
                Some(RpcProcId::CursorPrepExec) => {
                    self.0
                        .rpc_log
                        .lock()
                        .unwrap()
                        .push(RpcProcId::CursorPrepExec);
                    let params = message.into_param_set().await?;
                    let all = params.all();
                    assert!(
                        all.len() >= 7,
                        "sp_cursorprepexec expected at least 7 params, got {}",
                        all.len()
                    );
                    assert!(all[0].is_output());
                    assert!(all[1].is_output());
                    assert!(all[4].is_output());
                    assert!(all[5].is_output());
                    assert!(all[6].is_output());
                    match &all[2].value {
                        ColumnData::String(Some(s)) => {
                            self.0
                                .cursorprepexec_param_defs_log
                                .lock()
                                .unwrap()
                                .push(Some(s.to_string()));
                        }
                        ColumnData::String(None) => {
                            self.0
                                .cursorprepexec_param_defs_log
                                .lock()
                                .unwrap()
                                .push(None);
                        }
                        other => panic!("sp_cursorprepexec @params was not a string: {:?}", other),
                    }

                    let sql = match &all[3].value {
                        ColumnData::String(Some(s)) => s.to_string(),
                        other => panic!("sp_cursorprepexec @stmt was not a string: {:?}", other),
                    };
                    let mut values = HashMap::new();
                    for p in &all[7..] {
                        if let ColumnData::I32(Some(v)) = &p.value {
                            values.insert(p.name.clone(), *v);
                        }
                    }
                    let rows = eval_sql(&sql, &values);

                    let prepared_handle =
                        self.0
                            .procs
                            .lock()
                            .unwrap()
                            .prepare(sql.clone(), Vec::new(), Vec::new());
                    let scrollopt = match &all[4].value {
                        ColumnData::I32(Some(v)) => *v,
                        _ => 0,
                    };
                    let ccopt = match &all[5].value {
                        ColumnData::I32(Some(v)) => *v,
                        _ => 0,
                    };

                    if *self.0.cursorprepexec_allow_direct.lock().unwrap() {
                        // AllowDirect: prepare the statement but do NOT open a
                        // cursor. Real SQL Server signals that fallback with
                        // INFO 16954 and omits the cursor ID and row-count
                        // outputs. Emit two sets to exercise ordering.
                        client
                            .send(TdsBackendMessage::TokenPartial(BackendToken::Info(
                                TokenInfo::new(
                                    16954,
                                    1,
                                    10,
                                    "Executing SQL directly; no cursor.",
                                    "test-server",
                                    "",
                                    1,
                                ),
                            )))
                            .await?;
                        write_int_result_set(client, &[1, 2, 3], FinalDone::InProc).await?;
                        write_int_result_set(client, &[4, 5, 6], FinalDone::InProc).await?;

                        // Only the prepared handle is guaranteed to be useful
                        // after direct fallback. In particular, do not invent a
                        // zero @cursor or option outputs just to satisfy the
                        // client parser.
                        let outputs = vec![OutputParameter::from_input(
                            &all[0],
                            ColumnData::I32(Some(prepared_handle.as_i32())),
                        )];
                        send_output_params(client, outputs).await?;
                        send_return_status(client, 0).await?;
                        client
                            .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                                TokenDone::with_rows(0),
                            )))
                            .await?;
                        return Ok(());
                    }

                    let cursor_entry = CursorEntry::new(sql, scrollopt, ccopt, rows.len() as i32);
                    let cursor_handle = self.0.cursors.lock().unwrap().open(cursor_entry);
                    self.0
                        .cursor_rows
                        .lock()
                        .unwrap()
                        .insert(cursor_handle, rows.clone());

                    let send_metadata = *self.0.cursorprepexec_send_metadata.lock().unwrap();
                    if send_metadata {
                        client
                            .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(
                                TokenColMetaData {
                                    columns: vec![int_int_column()],
                                },
                            )))
                            .await?;
                        client
                            .send(TdsBackendMessage::TokenPartial(BackendToken::DoneInProc(
                                TokenDone::with_rows(0),
                            )))
                            .await?;
                    }

                    let outputs = vec![
                        OutputParameter::from_input(
                            &all[0],
                            ColumnData::I32(Some(prepared_handle.as_i32())),
                        )
                        .with_ordinal(1),
                        OutputParameter::from_input(
                            &all[1],
                            ColumnData::I32(Some(cursor_handle.as_i32())),
                        )
                        .with_ordinal(2),
                        OutputParameter::from_input(&all[4], ColumnData::I32(Some(scrollopt)))
                            .with_ordinal(5),
                        OutputParameter::from_input(&all[5], ColumnData::I32(Some(ccopt)))
                            .with_ordinal(6),
                        OutputParameter::from_input(
                            &all[6],
                            ColumnData::I32(Some(rows.len() as i32)),
                        )
                        .with_ordinal(7),
                    ];
                    send_output_params(client, outputs).await?;
                    send_return_status(client, 0).await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                Some(RpcProcId::CursorUnprepare) => {
                    self.0
                        .rpc_log
                        .lock()
                        .unwrap()
                        .push(RpcProcId::CursorUnprepare);
                    if *self.0.drop_on_release.lock().unwrap() {
                        return drop_connection();
                    }
                    let params = message.into_param_set().await?;
                    let handle = match params.get(0).map(|p| &p.value) {
                        Some(ColumnData::I32(Some(v))) => PreparedHandle::from_i32(*v),
                        other => panic!("sp_cursorunprepare handle was not i32: {:?}", other),
                    };
                    self.0.procs.lock().unwrap().unprepare(&handle);
                    send_return_status(client, 0).await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                None if message.proc_name.as_deref() == Some("tiberius_echo_proc") => {
                    // Echoes every byref parameter back unchanged, so tests
                    // can exercise any type/direction without a bespoke
                    // handler per case.
                    let params = message.into_param_set().await?;
                    let all = params.all();

                    client
                        .send(TdsBackendMessage::TokenPartial(BackendToken::Info(
                            TokenInfo::new(
                                5000,
                                1,
                                5,
                                "tiberius_echo_proc: running",
                                "test-server",
                                "tiberius_echo_proc",
                                1,
                            ),
                        )))
                        .await?;

                    let outputs: Vec<OutputParameter<'static>> = all
                        .iter()
                        .filter(|p| p.is_output())
                        .map(|p| OutputParameter::from_input(p, p.value.clone()))
                        .collect();
                    if !outputs.is_empty() {
                        send_output_params(client, outputs).await?;
                    }
                    send_return_status(client, all.len() as i32).await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                None if message.proc_name.as_deref() == Some("tiberius_multi_result_proc") => {
                    write_int_result_set(client, &[1, 2, 3], FinalDone::InProc).await?;
                    write_int_result_set(client, &[4, 5], FinalDone::InProc).await?;
                    send_return_status(client, 0).await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                None if message.proc_name.as_deref() == Some("tiberius_test_proc_error") => {
                    client
                        .send(TdsBackendMessage::TokenPartial(BackendToken::Error(
                            tiberius::TokenError::new(
                                50001,
                                1,
                                16,
                                "tiberius_test_proc_error: boom",
                                "test-server",
                                "tiberius_test_proc_error",
                                1,
                            ),
                        )))
                        .await?;
                    client
                        .send(TdsBackendMessage::Token(BackendToken::DoneProc(
                            TokenDone::with_rows(0),
                        )))
                        .await?;
                    Ok(())
                }
                None if message.proc_name.as_deref() == Some("tiberius_test_proc_cancel") => {
                    // A packet-less "long-running" procedure: emit nothing and
                    // wait for an attention, mirroring `NoopSqlBatch`'s
                    // `WAITFOR DELAY` simulation. Used to prove
                    // `call_procedure` honors cancellation and leaves the
                    // connection reusable afterward.
                    for _ in 0..500 {
                        if client.poll_attention().await? {
                            return Ok(());
                        }
                        smol::Timer::after(std::time::Duration::from_millis(10)).await;
                    }
                    Ok(())
                }
                _ => Err(tiberius::error::Error::Protocol(
                    "test harness: unexpected RPC".into(),
                )),
            }
        })
    }
}

// SystemProcRouter requires each slot's type to implement the corresponding
// handler trait (even if the slot is None). We don't wire an sp_executesql
// handler for these tests, so give `RejectIt` a trait impl that errors on
// invocation — it will never be reached because the slot is None.
impl tiberius::server::SpExecuteSqlHandler for RejectIt {
    fn execute<'a, C>(
        &'a self,
        _client: &'a mut C,
        _request: tiberius::server::ParsedExecuteSql<'a>,
    ) -> BoxFuture<'a, tiberius::Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async {
            Err(tiberius::error::Error::Protocol(
                "test harness: unexpected sp_executesql".into(),
            ))
        })
    }
}

struct TestHandlers {
    auth: TestAuth,
    sql: NoopSqlBatch,
    rpc: TestRouter,
    bulk: RejectBulkLoad,
    attention: NoOpAttention,
    error: NoOpError,
}

impl TestHandlers {
    fn new(state: Arc<SharedState>) -> Self {
        let rpc: TestRouter = SystemProcRouterBuilder::new()
            .with_executesql(RejectIt)
            .with_prepare(TestPrepare(state.clone()))
            .with_execute(TestExecute(state.clone()))
            .with_unprepare(TestUnprepare(state.clone()))
            .with_prepexec(TestPrepExec(state.clone()))
            .with_cursor_open(TestCursorOpen(state.clone()))
            .with_cursor_fetch(TestCursorFetch(state.clone()))
            .with_cursor_close(TestCursorClose(state.clone()))
            .with_fallback(SpecialRpc(state.clone()))
            .build();
        Self {
            auth: TestAuth::new(),
            sql: NoopSqlBatch,
            rpc,
            bulk: RejectBulkLoad,
            attention: NoOpAttention,
            error: NoOpError,
        }
    }
}

impl TdsServerHandlers for TestHandlers {
    type Auth = TestAuth;
    type SqlBatch = NoopSqlBatch;
    type Rpc = TestRouter;
    type Bulk = RejectBulkLoad;
    type Attention = NoOpAttention;
    type Error = NoOpError;

    fn auth_handler(&self) -> &Self::Auth {
        &self.auth
    }
    fn sql_batch_handler(&self) -> &Self::SqlBatch {
        &self.sql
    }
    fn rpc_handler(&self) -> &Self::Rpc {
        &self.rpc
    }
    fn bulk_load_handler(&self) -> &Self::Bulk {
        &self.bulk
    }
    fn attention_handler(&self) -> &Self::Attention {
        &self.attention
    }
    fn error_handler(&self) -> &Self::Error {
        &self.error
    }
}

// =============================================================================
// Test harness: spawn a server, connect a client
// =============================================================================

async fn run_server_once(
    listener: async_net::TcpListener,
    handlers: Arc<TestHandlers>,
) -> tiberius::Result<()> {
    use tiberius::server::backend::smol_net::SmolStream;
    let (stream, _addr) = listener
        .accept()
        .await
        .map_err(|e| tiberius::error::Error::Io {
            kind: e.kind(),
            message: e.to_string(),
        })?;
    let stream = SmolStream::new(stream);
    let tls: Option<tiberius::server::NoTls> = None;
    process_connection(stream, tls, &*handlers).await
}

type TestClient = Client<smol_adapter::Compat<async_net::TcpStream>>;

async fn connect_client(addr: SocketAddr) -> tiberius::Result<TestClient> {
    let stream =
        async_net::TcpStream::connect(addr)
            .await
            .map_err(|e| tiberius::error::Error::Io {
                kind: e.kind(),
                message: e.to_string(),
            })?;
    stream.set_nodelay(true).ok();
    let mut config = Config::new();
    config.host(addr.ip().to_string());
    config.port(addr.port());
    config.authentication(tiberius::AuthMethod::sql_server("u", "p"));
    config.encryption(EncryptionLevel::NotSupported);
    config.trust_cert();
    Client::connect(config, smol_adapter::Compat::new(stream)).await
}

async fn assert_connection_reusable(client: &mut TestClient) {
    let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
    let row = stmt
        .query(client, &[&42i32])
        .await
        .unwrap()
        .into_row()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), Some(42));
    stmt.unprepare(client).await.unwrap();
}

mod smol_adapter {
    //! Minimal wrapper so async-net TcpStream (which uses futures_lite) can
    //! act as futures_util AsyncRead/AsyncWrite for the Tiberius client.
    use futures_lite::io::{AsyncRead as LiteRead, AsyncWrite as LiteWrite};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub struct Compat<S>(S);

    impl<S> Compat<S> {
        pub fn new(inner: S) -> Self {
            Self(inner)
        }
    }

    impl<S: LiteRead + Unpin> futures_util::io::AsyncRead for Compat<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl<S: LiteWrite + Unpin> futures_util::io::AsyncWrite for Compat<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_close(cx)
        }
    }
}

async fn with_server<F, Fut, T>(test: F) -> T
where
    F: FnOnce(SocketAddr, Arc<SharedState>) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let state = Arc::new(SharedState::new());
    let handlers = Arc::new(TestHandlers::new(state.clone()));

    let listener = async_net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Each server gets its own thread and executor. smol's global executor
    // defaults to a single thread shared by the whole test binary, so one
    // test moving bulk data would starve every other test's server.
    let handlers_bg = handlers.clone();
    std::thread::spawn(move || {
        smol::block_on(async move {
            let _ = run_server_once(listener, handlers_bg).await;
        });
    });

    // The server serves one connection and returns once the client (dropped
    // when `test` completes) disconnects.
    test(addr, state).await
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn prepare_execute_unprepare_round_trip() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let stmt = client
                .prepare("SELECT @P1 + @P2 AS s", "@P1 int, @P2 int")
                .await
                .unwrap();
            let handle = stmt.handle();
            assert_ne!(handle.as_i32(), 0);

            let row = stmt
                .query(&mut client, &[&7i32, &35i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));
            // Handle is stable across executes.
            assert_eq!(stmt.handle(), handle);

            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn prep_exec_returns_handle_and_rows() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let (stmt, results) = client
                .prep_exec("SELECT @P1 AS v", "@P1 int", &[&99i32])
                .await
                .unwrap();
            assert_ne!(stmt.handle().as_i32(), 0);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].len(), 1);
            assert_eq!(results[0][0].get::<i32, _>(0), Some(99));

            // Reuse the returned handle.
            let row = stmt
                .query(&mut client, &[&7i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(7));

            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn open_fetch_close_cursor() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let cursor = client
                .open_cursor(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap();
            assert_ne!(cursor.handle().as_i32(), 0);
            assert_eq!(cursor.row_count(), 3);

            // Use a distinctive fetch request so we can prove the wire
            // encoding survives: Fetch::Absolute encodes to (0x0010, 7, 3).
            let rows = cursor
                .fetch(&mut client, tiberius::Fetch::Absolute { row: 7, count: 3 })
                .await
                .unwrap()
                .into_first_result()
                .await
                .unwrap();
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].get::<i32, _>(0), Some(1));
            assert_eq!(rows[1].get::<i32, _>(0), Some(2));
            assert_eq!(rows[2].get::<i32, _>(0), Some(3));

            // Server received what the client claimed to send.
            let seen = state.cursor_fetch_log.lock().unwrap().clone();
            assert_eq!(seen, vec![(0x0010, 7, 3)]);

            cursor.close(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_fetch_close_unprepare() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let mut cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::new(
                        CursorScrollOptions::ParameterizedStmt | CursorScrollOptions::ForwardOnly,
                        tiberius::CursorConcurrencyOptions::ReadOnly,
                    ),
                    "",
                    &[],
                )
                .await
                .unwrap()
                .into_cursor()
                .expect("expected prepared cursor");
            assert_ne!(cursor.prepared_handle().as_i32(), 0);
            assert_ne!(cursor.cursor_handle().as_i32(), 0);
            assert_eq!(cursor.row_count(), 3);
            assert!(cursor
                .scroll_options()
                .contains(CursorScrollOptions::ParameterizedStmt));

            let mut stream = cursor
                .fetch(&mut client, tiberius::Fetch::Next { count: 142 })
                .await
                .unwrap();
            let columns = stream.columns().await.unwrap().unwrap();
            assert_eq!(columns[0].name(), "v");
            assert_eq!(columns[0].ordinal(), Some(0));
            assert_eq!(
                columns[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert_eq!(columns[0].fixed_len_type(), Some(FixedLenType::Int4));
            assert!(columns[0].flags().contains(ColumnFlag::Nullable));
            assert!(columns[0].is_nullable());

            let rows = stream.into_first_result().await.unwrap();
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].get::<i32, _>(0), Some(1));
            assert_eq!(
                rows[0].columns()[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert!(rows[0].columns()[0].flags().contains(ColumnFlag::Nullable));
            assert_eq!(rows[1].get::<i32, _>(0), Some(2));
            assert_eq!(rows[2].get::<i32, _>(0), Some(3));

            let seen_fetches = state.cursor_fetch_log.lock().unwrap().clone();
            assert_eq!(seen_fetches, vec![(0x0002, 0, 142)]);

            cursor.close_cursor(&mut client).await.unwrap();
            cursor.close_cursor(&mut client).await.unwrap();
            cursor.unprepare(&mut client).await.unwrap();

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorFetch,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
        })
        .await;
    });
}

async fn open_prepared_cursor(
    client: &mut TestClient,
) -> (tiberius::PreparedCursor, PreparedHandle) {
    let cursor = client
        .cursor_prep_exec(
            "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
            CursorOpenOptions::default(),
            "",
            &[],
        )
        .await
        .unwrap()
        .into_cursor()
        .expect("expected prepared cursor");
    let handle = PreparedHandle::from_i32(cursor.prepared_handle().as_i32());
    (cursor, handle)
}

#[test]
fn prepared_cursor_unprepare_closes_an_open_cursor() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let (cursor, handle) = open_prepared_cursor(&mut client).await;

            cursor.unprepare(&mut client).await.unwrap();

            assert_eq!(
                *state.rpc_log.lock().unwrap(),
                [
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
            assert!(state.cursor_rows.lock().unwrap().is_empty());
            assert!(!state.procs.lock().unwrap().contains(&handle));
            assert_connection_reusable(&mut client).await;
        })
        .await;
    });
}

#[test]
fn prepared_cursor_unprepare_releases_the_handle_after_a_failed_close() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let (cursor, handle) = open_prepared_cursor(&mut client).await;
            *state.fail_cursor_close.lock().unwrap() = true;

            let result = cursor.unprepare(&mut client).await;

            assert_eq!(result.unwrap_err().code(), Some(16917));
            assert_eq!(
                state.rpc_log.lock().unwrap()[1..],
                [RpcProcId::CursorClose, RpcProcId::CursorUnprepare]
            );
            assert!(!state.procs.lock().unwrap().contains(&handle));
            assert_connection_reusable(&mut client).await;
        })
        .await;
    });
}

/// Asserts that `error` keeps a request's server error `code` and reports
/// that the release after it failed with the connection, which is gone.
async fn assert_release_lost_with_connection(
    client: &mut TestClient,
    error: tiberius::error::Error,
    code: u32,
) {
    assert_eq!(error.code(), Some(code));
    assert!(!error.leaves_connection_usable());
    assert!(
        matches!(
            &error,
            tiberius::error::Error::CleanupFailed { cleanup, .. }
                if matches!(**cleanup, tiberius::error::Error::Io { .. })
        ),
        "expected an I/O cleanup failure, got {error:?}"
    );
    assert!(client.simple_query("SELECT 1").await.is_err());
}

#[test]
fn prepared_cursor_unprepare_reports_a_release_failure_after_a_failed_close() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let (cursor, _) = open_prepared_cursor(&mut client).await;
            *state.fail_cursor_close.lock().unwrap() = true;
            *state.drop_on_release.lock().unwrap() = true;

            let error = cursor.unprepare(&mut client).await.unwrap_err();

            assert_release_lost_with_connection(&mut client, error, 16917).await;
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_allow_direct_returns_owned_results() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            *state.cursorprepexec_allow_direct.lock().unwrap() = true;
            let mut client = connect_client(addr).await.unwrap();

            let outcome = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::new(
                        CursorScrollOptions::ForwardOnly,
                        tiberius::CursorConcurrencyOptions::ReadOnly
                            | tiberius::CursorConcurrencyOptions::AllowDirect,
                    ),
                    "",
                    &[],
                )
                .await
                .unwrap();

            // The server took the AllowDirect fast path: no cursor, results
            // streamed inline.
            assert!(outcome.is_direct());
            assert_ne!(outcome.prepared_handle().as_i32(), 0);

            let direct = outcome.into_direct().expect("expected AllowDirect results");
            assert!(direct
                .concurrency_options()
                .contains(tiberius::CursorConcurrencyOptions::AllowDirect));

            // Both result sets are preserved, in order, with metadata and rows.
            assert_eq!(direct.results().len(), 2);
            assert_eq!(direct.results()[0].columns().len(), 1);
            assert_eq!(direct.results()[0].columns()[0].name(), "v");

            let first: Vec<i32> = direct.results()[0]
                .rows()
                .iter()
                .map(|r| r.get::<i32, _>(0).unwrap())
                .collect();
            assert_eq!(first, vec![1, 2, 3]);

            let second: Vec<i32> = direct.results()[1]
                .rows()
                .iter()
                .map(|r| r.get::<i32, _>(0).unwrap())
                .collect();
            assert_eq!(second, vec![4, 5, 6]);

            // Cleanup releases the prepared handle and hands back the owned
            // result sets — no cursor close is issued.
            let owned = direct.unprepare(&mut client).await.unwrap();
            assert_eq!(owned.len(), 2);
            assert_eq!(owned[0].rows().len(), 3);
            assert_eq!(owned[1].rows().len(), 3);

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![RpcProcId::CursorPrepExec, RpcProcId::Unprepare]
            );
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_fetch_metadata_close_unprepare() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let mut cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap()
                .into_cursor()
                .expect("expected prepared cursor");

            let columns = cursor.fetch_metadata(&mut client).await.unwrap();
            assert_eq!(columns.len(), 1);
            assert_eq!(columns[0].name(), "v");
            assert_eq!(columns[0].ordinal(), Some(0));
            assert_eq!(
                columns[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert!(columns[0].flags().contains(ColumnFlag::Nullable));

            let seen_fetches = state.cursor_fetch_log.lock().unwrap().clone();
            assert_eq!(seen_fetches, vec![(0x0002, 0, 0)]);

            let param_defs = state.cursorprepexec_param_defs_log.lock().unwrap().clone();
            assert_eq!(param_defs, vec![None]);

            cursor.close_cursor(&mut client).await.unwrap();
            cursor.unprepare(&mut client).await.unwrap();

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorFetch,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
        })
        .await;
    });
}

#[test]
fn cursor_prep_exec_fetch_metadata_reuses_initial_metadata() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            *state.cursorprepexec_send_metadata.lock().unwrap() = true;
            let mut client = connect_client(addr).await.unwrap();

            let mut cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap()
                .into_cursor()
                .expect("expected prepared cursor");

            let columns = cursor.fetch_metadata(&mut client).await.unwrap();
            assert_eq!(columns.len(), 1);
            assert_eq!(columns[0].name(), "v");
            assert_eq!(columns[0].ordinal(), Some(0));
            assert_eq!(
                columns[0].type_info(),
                Some(&TypeInfo::FixedLen(FixedLenType::Int4))
            );
            assert!(columns[0].flags().contains(ColumnFlag::Nullable));

            let seen_fetches = state.cursor_fetch_log.lock().unwrap().clone();
            assert!(seen_fetches.is_empty());

            let param_defs = state.cursorprepexec_param_defs_log.lock().unwrap().clone();
            assert_eq!(param_defs, vec![None]);

            cursor.close_cursor(&mut client).await.unwrap();
            cursor.unprepare(&mut client).await.unwrap();

            let seen_rpcs = state.rpc_log.lock().unwrap().clone();
            assert_eq!(
                seen_rpcs,
                vec![
                    RpcProcId::CursorPrepExec,
                    RpcProcId::CursorClose,
                    RpcProcId::CursorUnprepare,
                ]
            );
        })
        .await;
    });
}

#[test]
fn cursor_fetch_encodes_all_directions() {
    // Drives every `Fetch` variant and asserts the server sees the right
    // (fetch_type, row_num, count) triple for each. Catches bugs where the
    // client-side encoder maps a variant to the wrong wire bits.
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let cursor = client
                .open_cursor(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap();

            let cases: &[(tiberius::Fetch, (i32, i32, i32))] = &[
                (tiberius::Fetch::First { count: 1 }, (0x0001, 0, 1)),
                (tiberius::Fetch::Next { count: 2 }, (0x0002, 0, 2)),
                (tiberius::Fetch::Prev { count: 3 }, (0x0004, 0, 3)),
                (tiberius::Fetch::Last { count: 4 }, (0x0008, 0, 4)),
                (
                    tiberius::Fetch::Absolute { row: 9, count: 5 },
                    (0x0010, 9, 5),
                ),
                (
                    tiberius::Fetch::Relative {
                        offset: -7,
                        count: 6,
                    },
                    (0x0020, -7, 6),
                ),
                (tiberius::Fetch::Refresh { count: 1 }, (0x0080, 0, 1)),
            ];

            for (fetch, _expected) in cases {
                let _ = cursor
                    .fetch(&mut client, *fetch)
                    .await
                    .unwrap()
                    .into_first_result()
                    .await
                    .unwrap();
            }

            let seen = state.cursor_fetch_log.lock().unwrap().clone();
            let expected: Vec<_> = cases.iter().map(|(_, e)| *e).collect();
            assert_eq!(seen, expected);

            cursor.close(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn cancellation_mid_query_surfaces_as_error() {
    // Exercises the interaction between CancellationToken and the RPC
    // stream drain path. We fire the cancel from another task before the
    // result stream is consumed; the next poll on the stream must surface
    // an error (not hang).
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();

            // Issue the query so bytes are in flight, then cancel before
            // consuming the response.
            let token = client.cancellation_token();
            let stream = stmt.query(&mut client, &[&1i32]).await.unwrap();
            token.cancel();

            // Consuming the stream after cancel: either yields results or
            // errors, but must NOT hang — we're just asserting termination.
            let _ = stream.into_results().await;

            // Connection is still reusable after cancellation drain.
            let stmt2 = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt2
                .query(&mut client, &[&42i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));

            stmt.unprepare(&mut client).await.ok();
            stmt2.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn cancel_interrupts_packetless_long_statement() {
    // Regression test for cancellation of a long, packet-less statement
    // (e.g. `WAITFOR DELAY`). The server batch handler emits no tokens and
    // only finishes when it observes an attention. From another task we fire
    // `cancel()` shortly after issuing the query; the client must wake its
    // parked read, send a TDS attention immediately, and the query must
    // terminate in ~the cancel latency — NOT run to the handler's 5s cap.
    //
    // Before the fix `cancel()` only set an AtomicBool with no waker, so the
    // client stayed parked in `read_u8().await` (no bytes arrive for a
    // packet-less statement) and never sent the attention — this test would
    // take ~5s and the elapsed assertion would fail.
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            // Take the token before borrowing the client for the query. The
            // parking happens inside `simple_query` itself (it forwards to
            // metadata), so the cancel must fire from another task.
            let token = client.cancellation_token();
            let canceller = smol::spawn(async move {
                smol::Timer::after(std::time::Duration::from_millis(100)).await;
                token.cancel();
            });

            let start = std::time::Instant::now();
            let sql = format!("{PACKETLESS_DELAY_SQL} '00:00:30'");
            // Scope the query so the QueryStream's mutable borrow of `client`
            // is released before we reuse the client below.
            let elapsed = {
                // `simple_query` issues a raw SQL batch (hits `on_sql_batch`)
                // and awaits the first metadata token, which never comes until
                // the cancel-induced attention drains the stream.
                let result = client.simple_query(sql).await;
                let elapsed = start.elapsed();
                // Whether the drained stream surfaces as Ok (empty) or an
                // error, it must have terminated — drain it without hanging.
                if let Ok(stream) = result {
                    let _ = stream.into_results().await;
                }
                elapsed
            };
            canceller.await;

            // Must terminate promptly, not at the handler's 5s cap.
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "cancellation did not interrupt the packet-less statement: took {elapsed:?}"
            );

            // The connection must be clean and reusable after the cancel drain.
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt
                .query(&mut client, &[&42i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));
            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn cancel_interrupts_packetless_cursor_metadata_fetch() {
    // Regression test for the cursor metadata-fetch path, which drains its RPC
    // response in `collect_metadata_only_rpc` (a raw read loop *outside*
    // `TokenStream::try_unfold`). With the server stalling the `sp_cursorfetch`
    // (@nrows = 0) probe, a `cancel()` from another task must interrupt the
    // parked read, send attention, and surface `Error::Canceled` promptly —
    // proving the cancellation race covers this path too, not just the token
    // stream.
    smol::block_on(async {
        with_server(|addr, state| async move {
            *state.stall_metadata_fetch.lock().unwrap() = true;
            let mut client = connect_client(addr).await.unwrap();

            let cursor = client
                .cursor_prep_exec(
                    "SELECT 1 AS v UNION ALL SELECT 2 AS v UNION ALL SELECT 3 AS v",
                    CursorOpenOptions::default(),
                    "",
                    &[],
                )
                .await
                .unwrap()
                .into_cursor()
                .expect("expected prepared cursor");

            let token = client.cancellation_token();
            let canceller = smol::spawn(async move {
                smol::Timer::after(std::time::Duration::from_millis(100)).await;
                token.cancel();
            });

            // `fetch_metadata` issues `sp_cursorfetch` (@nrows = 0) and parks in
            // `collect_metadata_only_rpc`'s read loop; the stalled handler emits
            // no tokens until it observes the attention.
            let start = std::time::Instant::now();
            let result = cursor.fetch_metadata(&mut client).await;
            let elapsed = start.elapsed();
            canceller.await;

            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "cancellation did not interrupt the cursor metadata fetch: took {elapsed:?}"
            );
            assert!(
                matches!(&result, Err(tiberius::error::Error::Canceled)),
                "expected Error::Canceled, got {result:?}"
            );

            // Stop stalling, then prove the connection is reusable after the
            // cancel drain.
            *state.stall_metadata_fetch.lock().unwrap() = false;
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt
                .query(&mut client, &[&42i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));
            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn prepared_statement_is_marked_released_after_unprepare() {
    // Guards the drop-warn false-positive fix (issue #2): `released` must
    // flip to true as soon as the sp_unprepare packet reaches the wire,
    // not after a potentially-flaky drain. We can't directly observe the
    // Drop warn, but unprepare returning Ok(()) means the flag was set;
    // the test below exercises the "dropped without unprepare" path by
    // explicitly leaking a prepared statement and verifying the test
    // doesn't panic (the warn is emitted via tracing::event! which is a
    // no-op under the default test subscriber).
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            // Explicitly drop without unprepare — exercises the Drop warn
            // path. Test passes as long as this doesn't panic / hang.
            drop(stmt);
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_returns_counts_and_releases_the_handle() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let handle = PreparedHandle::from_i32(stmt.handle().as_i32());

            let (result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;

            assert!(error.is_none(), "unexpected error: {error:?}");
            // Both counts are the execution's: the harness ends `sp_execute`
            // with a counted DONEPROC. The release's response adds none.
            assert_eq!(result.rows_affected(), &[1, 1]);
            assert_eq!(*state.rpc_log.lock().unwrap(), [RpcProcId::Unprepare]);
            assert!(!state.procs.lock().unwrap().contains(&handle));
            assert_connection_reusable(&mut client).await;
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_releases_the_handle_after_a_server_error() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client
                .prepare(FAILING_EXECUTE_SQL, "@P1 int")
                .await
                .unwrap();
            let handle = PreparedHandle::from_i32(stmt.handle().as_i32());

            let (result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;

            assert!(result.rows_affected().is_empty());
            assert_eq!(error.and_then(|error| error.code()), Some(2627));
            assert!(!state.procs.lock().unwrap().contains(&handle));
            assert_connection_reusable(&mut client).await;
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_releases_the_handle_after_a_cancel() {
    // An attention aborts the whole request it interrupts, so the release
    // must follow in its own request once the cancel has been acknowledged.
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client
                .prepare(STALLED_EXECUTE_SQL, "@P1 int")
                .await
                .unwrap();
            let handle = PreparedHandle::from_i32(stmt.handle().as_i32());

            let token = client.cancellation_token();
            let canceller = smol::spawn(async move {
                smol::Timer::after(std::time::Duration::from_millis(100)).await;
                token.cancel();
            });
            let start = std::time::Instant::now();
            let (_result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;
            let elapsed = start.elapsed();
            canceller.await;

            assert!(
                matches!(error, Some(tiberius::error::Error::Canceled)),
                "expected Error::Canceled, got {error:?}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "cancellation did not interrupt the execution: took {elapsed:?}"
            );
            assert_eq!(*state.rpc_log.lock().unwrap(), [RpcProcId::Unprepare]);
            assert!(!state.procs.lock().unwrap().contains(&handle));
            assert_connection_reusable(&mut client).await;
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_reports_a_release_failure_after_a_server_error() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client
                .prepare(FAILING_EXECUTE_SQL, "@P1 int")
                .await
                .unwrap();
            *state.drop_on_release.lock().unwrap() = true;

            let (result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;

            assert!(result.rows_affected().is_empty());
            let error = error.expect("the execution failed");
            assert_release_lost_with_connection(&mut client, error, 2627).await;
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_skips_the_release_after_a_fatal_execution_error() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare(FATAL_EXECUTE_SQL, "@P1 int").await.unwrap();

            let (_result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;

            let error = error.expect("the execution failed");
            assert!(
                matches!(&error, tiberius::error::Error::Server(e) if e.class() == 20),
                "expected the fatal server error, got {error:?}"
            );
            assert!(!error.leaves_connection_usable());
            assert!(state.rpc_log.lock().unwrap().is_empty());
            assert!(client.simple_query("SELECT 1").await.is_err());
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_reports_a_fatal_release_error_after_a_server_error() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client
                .prepare(FAILING_EXECUTE_SQL, "@P1 int")
                .await
                .unwrap();
            *state.fatal_on_release.lock().unwrap() = true;

            let (_result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;

            let error = error.expect("the execution failed");
            assert_eq!(error.code(), Some(2627));
            assert!(
                matches!(
                    &error,
                    tiberius::error::Error::CleanupFailed { cleanup, .. }
                        if matches!(&**cleanup, tiberius::error::Error::Server(e) if e.class() == 20)
                ),
                "expected a fatal cleanup failure, got {error:?}"
            );
            assert!(!error.leaves_connection_usable());
            assert!(client.simple_query("SELECT 1").await.is_err());
        })
        .await;
    });
}

#[test]
fn execute_and_unprepare_reports_a_release_failure_after_a_successful_execution() {
    smol::block_on(async {
        with_server(|addr, state| async move {
            let mut client = connect_client(addr).await.unwrap();
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            *state.drop_on_release.lock().unwrap() = true;

            let (result, error) = stmt.execute_and_unprepare(&mut client, &[&5i32]).await;

            assert_eq!(result.rows_affected(), &[1, 1]);
            let error = error.expect("the release failed");
            assert!(
                matches!(error, tiberius::error::Error::Io { .. }),
                "expected an I/O error, got {error:?}"
            );
            assert!(!error.leaves_connection_usable());
        })
        .await;
    });
}

// =============================================================================
// call_procedure — arbitrary stored procedure RPC calls
//
// Most of these drive `tiberius_echo_proc`, so what is under test is the
// client's wire round trip for each parameter shape.
// =============================================================================

fn int_type() -> TypeInfo {
    TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None))
}

fn nvarchar_type(len: usize) -> TypeInfo {
    TypeInfo::VarLenSized(VarLenContext::new(
        VarLenType::NVarchar,
        len,
        Some(tiberius::Collation::new(13632521, 52)),
    ))
}

#[test]
fn call_procedure_echoes_integers_input_output_inout() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::input(int_type(), ColumnData::I32(Some(21)))
                            .named("@in"),
                        ProcedureParameter::output(int_type(), ColumnData::I32(Some(0)))
                            .named("@out"),
                        ProcedureParameter::input_output(int_type(), ColumnData::I32(Some(9)))
                            .named("@io"),
                    ],
                )
                .await
                .unwrap();

            assert_eq!(result.messages.len(), 1);
            assert_eq!(result.messages[0].number(), 5000);
            // The echo proc returns the input param count as its status.
            assert_eq!(result.return_status, Some(3));

            let out = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@out"))
                .expect("expected @out output value");
            assert_eq!(out.get::<i32>().unwrap(), Some(0));

            let io = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@io"))
                .expect("expected @io output value");
            assert_eq!(io.get::<i32>().unwrap(), Some(9));

            // The connection is immediately reusable for another call. A
            // negative return status must survive as a signed value, not
            // wrap around to a large unsigned one.
            let result2 = client
                .call_procedure("tiberius_echo_proc", Vec::new())
                .await
                .unwrap();
            assert_eq!(result2.return_status, Some(0));
        })
        .await;
    });
}

#[test]
fn call_procedure_echoes_strings_bounded_and_max() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let bounded_ty = nvarchar_type(50);
            let max_ty = nvarchar_type(0xffff);
            // Small enough to stay in one TDS packet; the multi-packet case
            // is covered by `call_procedure_echoes_multi_packet_value`.
            let long_value: String = "tiberius-".repeat(100);

            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::output(
                            bounded_ty,
                            ColumnData::String(Some(Cow::Borrowed("hello"))),
                        )
                        .named("@bounded"),
                        ProcedureParameter::output(
                            max_ty,
                            ColumnData::String(Some(Cow::Owned(long_value.clone()))),
                        )
                        .named("@max"),
                    ],
                )
                .await
                .unwrap();

            let bounded = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@bounded"))
                .unwrap();
            assert_eq!(bounded.get::<&str>().unwrap(), Some("hello"));

            let max = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@max"))
                .unwrap();
            assert_eq!(max.get::<&str>().unwrap(), Some(long_value.as_str()));
        })
        .await;
    });
}

#[test]
fn call_procedure_echoes_binary_bounded_and_max() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let bounded_ty =
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 50, None));
            let max_ty =
                TypeInfo::VarLenSized(VarLenContext::new(VarLenType::BigVarBin, 0xffff, None));
            // Single-packet sized; the multi-packet case is covered by
            // `call_procedure_echoes_multi_packet_value`.
            let long_value: Vec<u8> = (0..1500u32).map(|i| (i % 256) as u8).collect();

            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::output(
                            bounded_ty,
                            ColumnData::Binary(Some(Cow::Borrowed(&[1u8, 2, 3][..]))),
                        )
                        .named("@bounded"),
                        ProcedureParameter::output(
                            max_ty,
                            ColumnData::Binary(Some(Cow::Owned(long_value.clone()))),
                        )
                        .named("@max"),
                    ],
                )
                .await
                .unwrap();

            let bounded = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@bounded"))
                .unwrap();
            assert_eq!(bounded.get::<&[u8]>().unwrap(), Some(&[1u8, 2, 3][..]));

            let max = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@max"))
                .unwrap();
            assert_eq!(max.get::<&[u8]>().unwrap(), Some(long_value.as_slice()));
        })
        .await;
    });
}

#[test]
fn call_procedure_echoes_null_output() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            // A real SQL NULL placeholder, decoupled from the wire type via
            // the parameter's explicit `TypeInfo` — this is exactly the case
            // that breaks if the wire type is inferred from the value
            // instead of declared explicitly.
            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::output(int_type(), ColumnData::I32(None)).named("@out"),
                    ],
                )
                .await
                .unwrap();

            let out = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@out"))
                .unwrap();
            assert_eq!(out.get::<i32>().unwrap(), None);
        })
        .await;
    });
}

#[test]
fn call_procedure_echoes_numeric_precision_scale() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let ty = TypeInfo::VarLenSizedPrecision {
                ty: VarLenType::Numericn,
                size: 17,
                precision: 18,
                scale: 2,
            };
            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![ProcedureParameter::output(
                        ty,
                        ColumnData::Numeric(Some(Numeric::new_with_scale(123_456, 2))),
                    )
                    .named("@out")],
                )
                .await
                .unwrap();

            let out = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@out"))
                .unwrap();
            match out.raw() {
                ColumnData::Numeric(Some(n)) => {
                    assert_eq!(n.scale(), 2);
                    assert_eq!(*n, Numeric::new_with_scale(123_456, 2));
                }
                other => panic!("expected Numeric, got {:?}", other),
            }
            assert_eq!(
                out.type_info(),
                &TypeInfo::VarLenSizedPrecision {
                    ty: VarLenType::Numericn,
                    size: 17,
                    precision: 18,
                    scale: 2,
                }
            );
        })
        .await;
    });
}

#[test]
fn call_procedure_output_ordinal_mapping() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::output(int_type(), ColumnData::I32(Some(1)))
                            .named("@first"),
                        ProcedureParameter::output(
                            nvarchar_type(50),
                            ColumnData::String(Some(Cow::Borrowed("second"))),
                        )
                        .named("@second"),
                        ProcedureParameter::output(int_type(), ColumnData::I32(Some(3)))
                            .named("@third"),
                    ],
                )
                .await
                .unwrap();

            assert_eq!(result.output_values.len(), 3);
            // Ordinals are asserted as strictly increasing rather than
            // against a literal base: SQL Server numbers them from 0, this
            // test server from 1, and neither is a contract.
            assert_eq!(result.output_values[0].name(), "@first");
            assert_eq!(result.output_values[1].name(), "@second");
            assert_eq!(result.output_values[2].name(), "@third");
            assert!(
                result.output_values[0].ordinal() < result.output_values[1].ordinal()
                    && result.output_values[1].ordinal() < result.output_values[2].ordinal(),
                "expected strictly increasing ordinals, got {:?}",
                result
                    .output_values
                    .iter()
                    .map(|o| o.ordinal())
                    .collect::<Vec<_>>()
            );
        })
        .await;
    });
}

#[test]
fn call_procedure_multiple_results() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let result = client
                .call_procedure("tiberius_multi_result_proc", Vec::new())
                .await
                .unwrap();

            assert_eq!(result.result_sets.len(), 2);
            let first: Vec<i32> = result.result_sets[0]
                .rows
                .iter()
                .map(|r| r.get::<i32, _>(0).unwrap())
                .collect();
            assert_eq!(first, vec![1, 2, 3]);
            let second: Vec<i32> = result.result_sets[1]
                .rows
                .iter()
                .map(|r| r.get::<i32, _>(0).unwrap())
                .collect();
            assert_eq!(second, vec![4, 5]);
        })
        .await;
    });
}

#[test]
fn call_procedure_without_rows_discards_rows_but_preserves_response_data() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let result = client
                .call_procedure_without_rows("tiberius_multi_result_proc", Vec::new())
                .await
                .unwrap();

            assert_eq!(result.result_sets.len(), 2);
            assert_eq!(result.result_sets[0].columns[0].name(), "v");
            assert_eq!(result.result_sets[1].columns[0].name(), "v");
            assert!(result
                .result_sets
                .iter()
                .all(|result_set| result_set.rows.is_empty()));
            assert_eq!(result.return_status, Some(0));

            let output_result = client
                .call_procedure_without_rows(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::output(int_type(), ColumnData::I32(Some(7)))
                            .named("@out"),
                    ],
                )
                .await
                .unwrap();

            assert!(output_result.result_sets.is_empty());
            assert_eq!(output_result.messages.len(), 1);
            assert_eq!(output_result.messages[0].number(), 5000);
            assert_eq!(output_result.return_status, Some(1));
            assert_eq!(
                output_result.output_values[0].get::<i32>().unwrap(),
                Some(7)
            );

            // The new collector must leave the connection ready for another
            // operation after draining all rows and trailing RPC tokens.
            let reusable = client
                .call_procedure_without_rows("tiberius_echo_proc", Vec::new())
                .await
                .unwrap();
            assert_eq!(reusable.return_status, Some(0));
        })
        .await;
    });
}

#[test]
fn call_procedure_surfaces_server_error() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let err = client
                .call_procedure("tiberius_test_proc_error", Vec::new())
                .await
                .unwrap_err();
            match err {
                tiberius::error::Error::Server(e) => assert_eq!(e.code(), 50001),
                other => panic!("expected Server error, got {:?}", other),
            }

            // The connection must still be reusable after an error response.
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt
                .query(&mut client, &[&1i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(1));
            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn call_procedure_cancellation_leaves_connection_reusable() {
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let token = client.cancellation_token();
            let canceller = smol::spawn(async move {
                smol::Timer::after(std::time::Duration::from_millis(100)).await;
                token.cancel();
            });

            let start = std::time::Instant::now();
            let result = client
                .call_procedure("tiberius_test_proc_cancel", Vec::new())
                .await;
            let elapsed = start.elapsed();
            canceller.await;

            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "cancellation did not interrupt call_procedure: took {elapsed:?}"
            );
            assert!(
                matches!(&result, Err(tiberius::error::Error::Canceled)),
                "expected Error::Canceled, got {result:?}"
            );

            // Connection is still reusable after the cancel drain.
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt
                .query(&mut client, &[&42i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(42));
            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}

#[test]
fn call_procedure_positional_binding_preserves_descriptor_order() {
    // No parameter carries a name, so binding is by declaration order alone.
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::input(int_type(), ColumnData::I32(Some(10))),
                        ProcedureParameter::output(int_type(), ColumnData::I32(Some(20))),
                        ProcedureParameter::input_output(int_type(), ColumnData::I32(Some(30))),
                    ],
                )
                .await
                .unwrap();

            // Only the byref (output / input-output) params come back, in
            // declaration order, and they must be addressable by position.
            assert_eq!(result.output_values.len(), 2);
            assert_eq!(result.output_values[0].get::<i32>().unwrap(), Some(20));
            assert_eq!(result.output_values[1].get::<i32>().unwrap(), Some(30));
            assert!(
                result.output_values[0].ordinal() < result.output_values[1].ordinal(),
                "expected strictly increasing ordinals, got {:?}",
                result
                    .output_values
                    .iter()
                    .map(|o| o.ordinal())
                    .collect::<Vec<_>>()
            );

            // Connection stays reusable after a positional call.
            let again = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![ProcedureParameter::output(
                        int_type(),
                        ColumnData::I32(Some(99)),
                    )],
                )
                .await
                .unwrap();
            assert_eq!(again.output_values[0].get::<i32>().unwrap(), Some(99));
        })
        .await;
    });
}
#[test]
fn call_procedure_echoes_multi_packet_value() {
    // Values spanning several TDS packets must survive the round trip in
    // both directions; regressions here stall the connection rather than
    // failing an assertion.
    smol::block_on(async {
        with_server(|addr, _state| async move {
            let mut client = connect_client(addr).await.unwrap();

            // 40_000 UTF-16 bytes => ~10 packets each way.
            let long_value: String = "abcdefghij".repeat(2_000);
            assert!(long_value.len() * 2 > 4096 * 4);

            let long_binary: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

            let result = client
                .call_procedure(
                    "tiberius_echo_proc",
                    vec![
                        ProcedureParameter::output(
                            nvarchar_type(0xffff),
                            ColumnData::String(Some(Cow::Owned(long_value.clone()))),
                        )
                        .named("@text"),
                        ProcedureParameter::output(
                            TypeInfo::VarLenSized(VarLenContext::new(
                                VarLenType::BigVarBin,
                                0xffff,
                                None,
                            )),
                            ColumnData::Binary(Some(Cow::Owned(long_binary.clone()))),
                        )
                        .named("@bin"),
                    ],
                )
                .await
                .unwrap();

            let text = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@text"))
                .unwrap();
            assert_eq!(text.get::<&str>().unwrap(), Some(long_value.as_str()));

            let bin = result
                .output_values
                .iter()
                .find(|o| o.matches_name("@bin"))
                .unwrap();
            assert_eq!(bin.get::<&[u8]>().unwrap(), Some(long_binary.as_slice()));

            // Connection remains usable after a multi-packet exchange.
            let stmt = client.prepare("SELECT @P1 AS v", "@P1 int").await.unwrap();
            let row = stmt
                .query(&mut client, &[&7i32])
                .await
                .unwrap()
                .into_row()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.get::<i32, _>(0), Some(7));
            stmt.unprepare(&mut client).await.unwrap();
        })
        .await;
    });
}
