mod auth;
mod cancellation;
mod config;
mod connection;
mod cursor;
mod prepared;
mod rpc_call;
mod rpc_response;

mod tls;
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
mod tls_stream;

pub use auth::*;
pub(crate) use cancellation::{CancelSignal, CancellationState};
pub use cancellation::CancellationToken;
pub use config::*;
pub(crate) use connection::*;
pub use cursor::{
    Cursor, CursorConcurrencyOptions, CursorHandle, CursorOpenOptions, CursorPrepExecOutcome,
    CursorScrollOptions, DirectResultSet, DirectResults, Fetch, PreparedCursor,
};
pub use prepared::{PreparedHandle, PreparedStatement};
pub use rpc_call::{ParameterDirection, ProcedureParameter, ProcedureResult};
pub use rpc_response::{BufferedResultSet, OutputValue};

use crate::tds::stream::ReceivedToken;
use crate::{
    result::ExecuteResult,
    tds::{
        codec::{self, IteratorJoin},
        stream::{QueryStream, TokenStream},
    },
    BulkLoadRequest, ColumnFlag, SqlReadBytes, ToSql,
};
use codec::{
    BatchRequest, ColumnData, PacketHeader, RpcParam, RpcProcId, RpcProcIdValue, TokenRpcRequest,
    TransactionOutcome, TransactionRequest,
};
use enumflags2::BitFlags;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::TryStreamExt;
use std::{borrow::Cow, fmt::Debug};

/// `Client` is the main entry point to the SQL Server, providing query
/// execution capabilities.
///
/// A `Client` is created using the [`Config`], defining the needed
/// connection options and capabilities.
///
/// # Example
///
/// ```no_run
/// # use tiberius::{Config, AuthMethod};
/// use tokio_util::compat::TokioAsyncWriteCompatExt;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut config = Config::new();
///
/// config.host("0.0.0.0");
/// config.port(1433);
/// config.authentication(AuthMethod::sql_server("SA", "<Mys3cureP4ssW0rD>"));
///
/// let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
/// tcp.set_nodelay(true)?;
/// // Client is ready to use.
/// let client = tiberius::Client::connect(config, tcp.compat_write()).await?;
/// # Ok(())
/// # }
/// ```
///
/// [`Config`]: struct.Config.html
#[derive(Debug)]
pub struct Client<S: AsyncRead + AsyncWrite + Unpin + Send> {
    pub(crate) connection: Connection<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Client<S> {
    /// Uses an instance of [`Config`] to specify the connection
    /// options required to connect to the database using an established
    /// tcp connection
    ///
    /// [`Config`]: struct.Config.html
    pub async fn connect(config: Config, tcp_stream: S) -> crate::Result<Client<S>> {
        Ok(Client {
            connection: Connection::connect(config, tcp_stream).await?,
        })
    }

    /// Executes SQL statements in the SQL Server, returning the number rows
    /// affected. Useful for `INSERT`, `UPDATE` and `DELETE` statements. The
    /// `query` can define the parameter placement by annotating them with
    /// `@PN`, where N is the index of the parameter, starting from `1`. If
    /// executing multiple queries at a time, delimit them with `;` and refer to
    /// [`ExecuteResult`] how to get results for the separate queries.
    ///
    /// For mapping of Rust types when writing, see the documentation for
    /// [`ToSql`]. For reading data from the database, see the documentation for
    /// [`FromSql`].
    ///
    /// This API is not quite suitable for dynamic query parameters. In these
    /// cases using a [`Query`] object might be easier.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let results = client
    ///     .execute(
    ///         "INSERT INTO ##Test (id) VALUES (@P1), (@P2), (@P3)",
    ///         &[&1i32, &2i32, &3i32],
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`ExecuteResult`]: struct.ExecuteResult.html
    /// [`ToSql`]: trait.ToSql.html
    /// [`FromSql`]: trait.FromSql.html
    /// [`Query`]: struct.Query.html
    pub async fn execute<'a>(
        &mut self,
        query: impl Into<Cow<'a, str>>,
        params: &[&dyn ToSql],
    ) -> crate::Result<ExecuteResult> {
        self.connection.flush_stream().await?;
        let rpc_params = Self::rpc_params(query);

        let params = params.iter().map(|s| s.to_sql());
        self.rpc_perform_query(RpcProcId::ExecuteSQL, rpc_params, params)
            .await?;

        ExecuteResult::new(&mut self.connection).await
    }

    /// Executes `query` through `sp_executesql` with the caller's parameter
    /// declarations, such as `"@P1 int, @P2 nvarchar(10)"`, rather than ones
    /// derived from each value. Values are passed as `@P1` onward, in order.
    ///
    /// Returns the row counts the server reported before the first error,
    /// with that error, or `None` when the execution succeeded. Counts
    /// reported after the error are dropped, even when later statements of a
    /// multi-statement batch ran.
    pub async fn execute_declared_until_error<'a>(
        &mut self,
        query: impl Into<Cow<'a, str>>,
        param_defs: impl Into<Cow<'a, str>>,
        params: &[&dyn ToSql],
    ) -> (ExecuteResult, Option<crate::Error>) {
        if let Err(error) = self.connection.flush_stream().await {
            return (ExecuteResult::empty(), Some(error));
        }
        let mut rpc_params = Self::rpc_params(query);
        rpc_params[1].value = ColumnData::String(Some(param_defs.into()));
        for (index, param) in params.iter().enumerate() {
            rpc_params.push(RpcParam {
                name: Cow::Owned(format!("@P{}", index + 1)),
                flags: BitFlags::empty(),
                type_info: None,
                value: param.to_sql(),
            });
        }
        if let Err(error) = self.send_rpc(RpcProcId::ExecuteSQL, rpc_params).await {
            return (ExecuteResult::empty(), Some(error));
        }
        ExecuteResult::until_error(&mut self.connection).await
    }

    /// Executes SQL statements in the SQL Server, returning resulting rows.
    /// Useful for `SELECT` statements. The `query` can define the parameter
    /// placement by annotating them with `@PN`, where N is the index of the
    /// parameter, starting from `1`. If executing multiple queries at a time,
    /// delimit them with `;` and refer to [`QueryStream`] on proper stream
    /// handling.
    ///
    /// For mapping of Rust types when writing, see the documentation for
    /// [`ToSql`]. For reading data from the database, see the documentation for
    /// [`FromSql`].
    ///
    /// This API can be cumbersome for dynamic query parameters. In these cases,
    /// if fighting too much with the compiler, using a [`Query`] object might be
    /// easier.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let stream = client
    ///     .query(
    ///         "SELECT @P1, @P2, @P3",
    ///         &[&1i32, &2i32, &3i32],
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`QueryStream`]: struct.QueryStream.html
    /// [`Query`]: struct.Query.html
    /// [`ToSql`]: trait.ToSql.html
    /// [`FromSql`]: trait.FromSql.html
    pub async fn query<'a, 'b>(
        &'a mut self,
        query: impl Into<Cow<'b, str>>,
        params: &'b [&'b dyn ToSql],
    ) -> crate::Result<QueryStream<'a>>
    where
        'a: 'b,
    {
        self.connection.flush_stream().await?;
        let rpc_params = Self::rpc_params(query);

        let params = params.iter().map(|p| p.to_sql());
        self.rpc_perform_query(RpcProcId::ExecuteSQL, rpc_params, params)
            .await?;

        let ts = TokenStream::new(&mut self.connection);
        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;

        Ok(result)
    }

    /// Execute multiple queries, delimited with `;` and return multiple result
    /// sets; one for each query.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let row = client.simple_query("SELECT 1 AS col").await?.into_row().await?.unwrap();
    /// assert_eq!(Some(1i32), row.get("col"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Warning
    ///
    /// Do not use this with any user specified input. Please resort to prepared
    /// statements using the [`query`] method.
    ///
    /// [`query`]: #method.query
    pub async fn simple_query<'a, 'b>(
        &'a mut self,
        query: impl Into<Cow<'b, str>>,
    ) -> crate::Result<QueryStream<'a>>
    where
        'a: 'b,
    {
        self.connection.flush_stream().await?;

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::batch(id), req).await?;

        let ts = TokenStream::new(&mut self.connection);

        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;

        Ok(result)
    }

    /// Whether the server has reported an open transaction on this
    /// connection. It sends the transaction's descriptor when one begins,
    /// including an implicit transaction, and clears it when one ends.
    pub fn transaction_open(&self) -> bool {
        self.connection.context().transaction_descriptor() != [0; 8]
    }

    /// Commits the session's transaction with a transaction manager request,
    /// which the server runs without compiling a batch. Returns `false`
    /// without contacting the server when the server has reported no open
    /// transaction on this connection.
    pub async fn commit_transaction(&mut self) -> crate::Result<bool> {
        self.end_transaction(TransactionOutcome::Commit).await
    }

    /// Rolls back the session's transaction as
    /// [`commit_transaction`](Self::commit_transaction) commits it.
    pub async fn rollback_transaction(&mut self) -> crate::Result<bool> {
        self.end_transaction(TransactionOutcome::Rollback).await
    }

    async fn end_transaction(&mut self, outcome: TransactionOutcome) -> crate::Result<bool> {
        self.connection.flush_stream().await?;
        let descriptor = self.connection.context().transaction_descriptor();
        if descriptor == [0; 8] {
            return Ok(false);
        }

        let id = self.connection.context_mut().next_packet_id();
        self.connection
            .send(
                PacketHeader::transaction_manager(id),
                TransactionRequest::new(outcome, descriptor),
            )
            .await?;
        // The server's ENVCHANGE for the commit or rollback clears the
        // descriptor while the response is read.
        let mut tokens = TokenStream::new(&mut self.connection).try_unfold();
        while tokens.try_next().await?.is_some() {}
        Ok(true)
    }

    /// Execute a `BULK INSERT` statement, efficiantly storing a large number of
    /// rows to a specified table. Note: make sure the input row follows the same
    /// schema as the table, otherwise calling `send()` will return an error.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::{Config, IntoRow};
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let create_table = r#"
    ///     CREATE TABLE ##bulk_test (
    ///         id INT IDENTITY PRIMARY KEY,
    ///         val INT NOT NULL
    ///     )
    /// "#;
    ///
    /// client.simple_query(create_table).await?;
    ///
    /// // Start the bulk insert with the client.
    /// let mut req = client.bulk_insert("##bulk_test").await?;
    ///
    /// for i in [0i32, 1i32, 2i32] {
    ///     let row = (i).into_row();
    ///
    ///     // The request will handle flushing to the wire in an optimal way,
    ///     // balancing between memory usage and IO performance.
    ///     req.send(row).await?;
    /// }
    ///
    /// // The request must be finalized.
    /// let res = req.finalize().await?;
    /// assert_eq!(3, res.total());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bulk_insert<'a>(
        &'a mut self,
        table: &'a str,
    ) -> crate::Result<BulkLoadRequest<'a, S>> {
        // Start the bulk request
        self.connection.flush_stream().await?;

        // retrieve column metadata from server
        let query = format!("SELECT TOP 0 * FROM {}", table);

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::batch(id), req).await?;

        let token_stream = TokenStream::new(&mut self.connection).try_unfold();

        let columns = token_stream
            .try_fold(None, |mut columns, token| async move {
                if let ReceivedToken::NewResultset(metadata) = token {
                    columns = Some(metadata.columns.clone());
                };

                Ok(columns)
            })
            .await?;

        // now start bulk upload
        let columns: Vec<_> = columns
            .ok_or_else(|| {
                crate::Error::Protocol("expecting column metadata from query but not found".into())
            })?
            .into_iter()
            .filter(|column| column.base.flags.contains(ColumnFlag::Updateable))
            .collect();

        self.connection.flush_stream().await?;
        let col_data = columns.iter().map(|c| format!("{}", c)).join(", ");
        let query = format!("INSERT BULK {} ({})", table, col_data);

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());
        let id = self.connection.context_mut().next_packet_id();

        self.connection.send(PacketHeader::batch(id), req).await?;

        let ts = TokenStream::new(&mut self.connection);
        ts.flush_done().await?;

        BulkLoadRequest::new(&mut self.connection, columns)
    }

    /// Closes this database connection explicitly.
    pub async fn close(self) -> crate::Result<()> {
        self.connection.close().await
    }

    /// Returns a cancellation token that can be used to cancel in-flight
    /// queries from another task.
    ///
    /// The token is `Clone` and `Send + Sync`, so it can be shared freely.
    /// Calling [`CancellationToken::cancel()`] causes the active
    /// [`QueryStream`] to terminate cleanly at its next poll point by
    /// sending a TDS attention signal to the server.
    ///
    /// [`QueryStream`]: struct.QueryStream.html
    pub fn cancellation_token(&self) -> CancellationToken {
        self.connection.cancellation_token()
    }

    /// Cancel any pending operation and flush the connection.
    ///
    /// Sends an attention signal to the server and drains the response
    /// stream. This is useful when you need to ensure the connection is
    /// clean before starting a new operation.
    ///
    /// If no operation is pending, this is a no-op.
    pub async fn cancel(&mut self) -> crate::Result<()> {
        self.connection.flush_stream().await
    }

    pub(crate) fn rpc_params<'a>(query: impl Into<Cow<'a, str>>) -> Vec<RpcParam<'a>> {
        vec![
            RpcParam {
                name: Cow::Borrowed("stmt"),
                flags: BitFlags::empty(),
                type_info: None,
                value: ColumnData::String(Some(query.into())),
            },
            RpcParam {
                name: Cow::Borrowed("params"),
                flags: BitFlags::empty(),
                type_info: None,
                value: ColumnData::I32(Some(0)),
            },
        ]
    }

    pub(crate) async fn rpc_perform_query<'a, 'b>(
        &'a mut self,
        proc_id: RpcProcId,
        mut rpc_params: Vec<RpcParam<'b>>,
        params: impl Iterator<Item = ColumnData<'b>>,
    ) -> crate::Result<()>
    where
        'a: 'b,
    {
        let mut param_str = String::new();

        for (i, param) in params.enumerate() {
            if i > 0 {
                param_str.push(',')
            }
            param_str.push_str(&format!("@P{} ", i + 1));
            param_str.push_str(&param.type_name());

            rpc_params.push(RpcParam {
                name: Cow::Owned(format!("@P{}", i + 1)),
                flags: BitFlags::empty(),
                type_info: None,
                value: param,
            });
        }

        if let Some(params) = rpc_params.iter_mut().find(|x| x.name == "params") {
            params.value = ColumnData::String(Some(param_str.into()));
        }

        self.send_rpc(proc_id, rpc_params).await
    }

    /// Send an RPC request with the given proc id (or arbitrary procedure
    /// name) and already-built parameters.
    ///
    /// Unlike [`rpc_perform_query`], this does not manipulate the `@params`
    /// definitions string — the caller is fully responsible for the parameter
    /// layout. Used by prepared statement and cursor helpers where the wire
    /// layout differs from `sp_executesql`, as well as by
    /// [`call_procedure`](Self::call_procedure).
    pub(crate) async fn send_rpc<'b>(
        &mut self,
        proc_id: impl Into<RpcProcIdValue<'b>>,
        rpc_params: Vec<RpcParam<'b>>,
    ) -> crate::Result<()> {
        let req = TokenRpcRequest::new(
            proc_id,
            rpc_params,
            self.connection.context().transaction_descriptor(),
        );

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::rpc(id), req).await?;

        Ok(())
    }

    /// Prepare a SQL statement on the server and return a handle that can be
    /// re-executed with different parameter values via
    /// [`PreparedStatement::query`] / [`PreparedStatement::execute`].
    ///
    /// `param_defs` is the parameter declaration string in SQL Server syntax,
    /// e.g. `"@P1 int, @P2 nvarchar(50)"`. Parameter names passed to
    /// subsequent `execute` / `query` calls must match those declarations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = Config::new();
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let stmt = client
    ///     .prepare("SELECT @P1 + @P2", "@P1 int, @P2 int")
    ///     .await?;
    /// let row = stmt
    ///     .query(&mut client, &[&1i32, &2i32])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    /// assert_eq!(Some(3i32), row.get(0));
    /// stmt.unprepare(&mut client).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn prepare<'a>(
        &mut self,
        sql: impl Into<Cow<'a, str>>,
        param_defs: impl Into<Cow<'a, str>>,
    ) -> crate::Result<PreparedStatement> {
        let sql: Cow<'a, str> = sql.into();
        let param_defs: Cow<'a, str> = param_defs.into();
        let sql_owned = sql.to_string();
        let defs_owned = param_defs.to_string();

        self.connection.flush_stream().await?;
        let rpc_params = prepared::build_prepare_params(sql, param_defs);
        self.send_rpc(RpcProcId::Prepare, rpc_params).await?;

        let (outputs, _status) = rpc_response::collect_rpc_outputs(&mut self.connection).await?;
        let handle = prepared::extract_handle(&outputs)?;

        Ok(PreparedStatement::new(handle, sql_owned, defs_owned))
    }

    /// Open a server-side cursor over the given SQL statement.
    ///
    /// `param_defs` follows the same format as [`prepare`](Self::prepare)
    /// (`"@P1 int, @P2 nvarchar(50)"` etc.); pass an empty string if the
    /// statement has no parameters.
    ///
    /// Use [`Cursor::fetch`] to page through rows and [`Cursor::close`] when
    /// done.
    pub async fn open_cursor<'a>(
        &mut self,
        sql: impl Into<Cow<'a, str>>,
        options: cursor::CursorOpenOptions,
        param_defs: impl Into<Cow<'a, str>>,
        params: &[&'a dyn ToSql],
    ) -> crate::Result<Cursor> {
        self.connection.flush_stream().await?;
        let rpc_params =
            cursor::build_cursoropen_params(sql.into(), options, param_defs.into(), params);
        self.send_rpc(RpcProcId::CursorOpen, rpc_params).await?;

        // sp_cursoropen does not produce a result set on open — only output
        // parameters + return status + DoneProc.
        let (outputs, _status) = rpc_response::collect_rpc_outputs(&mut self.connection).await?;
        cursor::cursor_from_outputs(&outputs)
    }

    /// Prepare a statement and open a cursor over its first execution in one
    /// round trip using `sp_cursorprepexec`.
    ///
    /// `param_defs` follows the same format as [`prepare`](Self::prepare);
    /// pass an empty string when the statement has no parameters.
    ///
    /// The return value is a [`CursorPrepExecOutcome`]: usually the server
    /// opens a cursor ([`Cursor`](CursorPrepExecOutcome::Cursor)), but when the
    /// statement is opened read-only with
    /// [`CursorConcurrencyOptions::AllowDirect`] the server may take the
    /// *AllowDirect* fast path — preparing the statement but skipping the
    /// cursor and streaming the result sets inline
    /// ([`Direct`](CursorPrepExecOutcome::Direct)). Either way the prepared
    /// handle must be released (via [`PreparedCursor::unprepare`] or
    /// [`DirectResults::unprepare`]).
    pub async fn cursor_prep_exec<'a>(
        &mut self,
        sql: impl Into<Cow<'a, str>>,
        options: cursor::CursorOpenOptions,
        param_defs: impl Into<Cow<'a, str>>,
        params: &[&'a dyn ToSql],
    ) -> crate::Result<CursorPrepExecOutcome> {
        self.connection.flush_stream().await?;
        let rpc_params =
            cursor::build_cursorprepexec_params(sql.into(), options, param_defs.into(), params);
        self.send_rpc(RpcProcId::CursorPrepExec, rpc_params).await?;

        let (result_sets, outputs, _status, infos) =
            rpc_response::collect_rpc_result_sets(&mut self.connection).await?;
        cursor::cursor_prep_exec_outcome(&outputs, result_sets, &infos, options)
    }

    /// Prepare and execute a SQL statement in a single round trip. Returns
    /// the handle alongside the buffered result rows from the first
    /// execution.
    ///
    /// For subsequent executions use [`PreparedStatement::query`] or
    /// [`PreparedStatement::execute`] on the returned handle.
    ///
    /// Unlike [`query`](Self::query), results are fully buffered rather
    /// than streamed — the trailing `@handle` output parameter only arrives
    /// after the result set, so streaming would require the caller to fully
    /// consume the stream before seeing the handle. If you need to stream
    /// the first execution, use [`prepare`](Self::prepare) followed by
    /// [`PreparedStatement::query`] (two round trips).
    pub async fn prep_exec<'a>(
        &mut self,
        sql: impl Into<Cow<'a, str>>,
        param_defs: impl Into<Cow<'a, str>>,
        params: &[&'a dyn ToSql],
    ) -> crate::Result<(PreparedStatement, Vec<Vec<crate::Row>>)> {
        let sql: Cow<'a, str> = sql.into();
        let param_defs: Cow<'a, str> = param_defs.into();
        let sql_owned = sql.to_string();
        let defs_owned = param_defs.to_string();

        self.connection.flush_stream().await?;
        let rpc_params = prepared::build_prepexec_params(sql, param_defs, params);
        self.send_rpc(RpcProcId::PrepExec, rpc_params).await?;

        let (results, outputs) = collect_prep_exec_results(&mut self.connection).await?;
        let handle = prepared::extract_handle(&outputs)?;

        Ok((
            PreparedStatement::new(handle, sql_owned, defs_owned),
            results,
        ))
    }

    /// Prepares and executes `sql` in one round trip, like
    /// [`prep_exec`](Self::prep_exec), but returns the first execution's row
    /// counts instead of its rows, as
    /// [`execute_declared_until_error`](Self::execute_declared_until_error)
    /// does.
    ///
    /// The statement is returned whenever the server assigned a handle, even
    /// when the execution failed, so the caller can still release it.
    pub async fn prep_exec_until_error<'a>(
        &mut self,
        sql: impl Into<Cow<'a, str>>,
        param_defs: impl Into<Cow<'a, str>>,
        params: &[&'a dyn ToSql],
    ) -> (
        Option<PreparedStatement>,
        ExecuteResult,
        Option<crate::Error>,
    ) {
        let sql: Cow<'a, str> = sql.into();
        let param_defs: Cow<'a, str> = param_defs.into();
        let sql_owned = sql.to_string();
        let defs_owned = param_defs.to_string();

        if let Err(error) = self.connection.flush_stream().await {
            return (None, ExecuteResult::empty(), Some(error));
        }
        let rpc_params = prepared::build_prepexec_params(sql, param_defs, params);
        if let Err(error) = self.send_rpc(RpcProcId::PrepExec, rpc_params).await {
            return (None, ExecuteResult::empty(), Some(error));
        }

        let mut outputs: Vec<OutputValue> = Vec::new();
        let (result, error) = ExecuteResult::until_error_visiting(&mut self.connection, |token| {
            if let ReceivedToken::ReturnValue(value) = token {
                outputs.push((*value).into());
            }
        })
        .await;
        let statement = prepared::extract_handle(&outputs)
            .ok()
            .map(|handle| PreparedStatement::new(handle, sql_owned, defs_owned));
        (statement, result, error)
    }
}

/// Drain the response of an `sp_prepexec` call: collect all result sets into
/// a `Vec<Vec<Row>>`, accumulating `RETURNVALUE` tokens (the `@handle` output
/// arrives at the tail) and terminating when the final `DONEPROC` without the
/// `More` flag is observed.
async fn collect_prep_exec_results<S>(
    conn: &mut Connection<S>,
) -> crate::Result<(Vec<Vec<crate::Row>>, Vec<OutputValue>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use crate::tds::codec::DoneStatus;
    use crate::{Column, Row};
    use std::sync::Arc;

    let ts = TokenStream::new(conn);
    let mut stream = ts.try_unfold();

    let mut results: Vec<Vec<Row>> = Vec::new();
    let mut current: Vec<Row> = Vec::new();
    let mut columns: Option<Arc<Vec<Column>>> = None;
    let mut result_index: usize = 0;
    let mut outputs: Vec<OutputValue> = Vec::new();
    let mut last_error: Option<crate::Error> = None;

    while let Some(tok) = stream.try_next().await? {
        match tok {
            ReceivedToken::NewResultset(meta) => {
                if columns.is_some() {
                    results.push(std::mem::take(&mut current));
                    result_index += 1;
                }
                let column_meta = meta.columns().collect::<Vec<_>>();
                columns = Some(Arc::new(column_meta));
            }
            ReceivedToken::Row(data) => {
                if let Some(cols) = &columns {
                    current.push(Row {
                        columns: cols.clone(),
                        data,
                        result_index,
                    });
                }
            }
            ReceivedToken::ReturnValue(rv) => outputs.push((*rv).into()),
            ReceivedToken::Error(e) => {
                last_error.get_or_insert(crate::Error::Server(e));
            }
            ReceivedToken::DoneInProc(ref done)
                if !done.status().contains(DoneStatus::More) =>
            {
                if columns.is_some() {
                    results.push(std::mem::take(&mut current));
                    columns = None;
                }
                // DoneInProc without More closes one statement's result set
                // inside the proc, but more tokens (like ReturnValue and
                // DoneProc) still follow — keep draining.
            }
            ReceivedToken::Done(ref done) | ReceivedToken::DoneProc(ref done)
                if !done.status().contains(DoneStatus::More) =>
            {
                if columns.is_some() {
                    results.push(std::mem::take(&mut current));
                    columns = None;
                }
                break;
            }
            _ => {}
        }
    }

    if let Some(err) = last_error {
        return Err(err);
    }

    Ok((results, outputs))
}
