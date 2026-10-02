pub use crate::tds::stream::{QueryItem, ResultMetadata};
use crate::{
    client::Connection,
    tds::stream::{ReceivedToken, TokenStream},
};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::{Stream, TryStreamExt};
use std::fmt::Debug;

/// A result from a query execution, listing the number of affected rows.
///
/// If executing multiple queries, the resulting counts will be come separately,
/// marking the rows affected for each query.
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
/// let result = client
///     .execute(
///         "INSERT INTO #Test (id) VALUES (@P1); INSERT INTO #Test (id) VALUES (@P2, @P3)",
///         &[&1i32, &2i32, &3i32],
///     )
///     .await?;
///
/// assert_eq!(&[1, 2], result.rows_affected());
/// # Ok(())
/// # }
/// ```
///
/// [`Client`]: struct.Client.html
/// [`Rows`]: struct.Row.html
/// [`next_resultset`]: #method.next_resultset
#[derive(Debug)]
pub struct ExecuteResult {
    rows_affected: Vec<u64>,
}

impl<'a> ExecuteResult {
    pub(crate) async fn new<S: AsyncRead + AsyncWrite + Unpin + Send>(
        connection: &'a mut Connection<S>,
    ) -> crate::Result<Self> {
        let mut token_stream = TokenStream::new(connection).try_unfold();
        let mut rows_affected = Vec::new();

        while let Some(token) = token_stream.try_next().await? {
            match token {
                ReceivedToken::DoneProc(done) if done.is_final() => (),
                ReceivedToken::DoneProc(done) => rows_affected.push(done.rows()),
                ReceivedToken::DoneInProc(done) => rows_affected.push(done.rows()),
                ReceivedToken::Done(done) => rows_affected.push(done.rows()),
                _ => (),
            }
        }

        Ok(Self { rows_affected })
    }

    pub(crate) fn empty() -> Self {
        Self {
            rows_affected: Vec::new(),
        }
    }

    /// Reads a response like [`new`](Self::new), but keeps the row counts
    /// that arrived before it failed. They are returned with the first server
    /// error, or with the transport, protocol, or cancellation error that
    /// ended the response. A server error does not end the response, so the
    /// rest of it is drained and its counts are dropped.
    pub(crate) async fn until_error<S: AsyncRead + AsyncWrite + Unpin + Send>(
        connection: &'a mut Connection<S>,
    ) -> (Self, Option<crate::Error>) {
        Self::until_error_visiting(connection, |_| ()).await
    }

    /// Like [`until_error`](Self::until_error), and passes `visit` every token
    /// that is neither an error nor a `DONE` variant, including those after
    /// the error, such as an output parameter at the end of the response.
    pub(crate) async fn until_error_visiting<S, F>(
        connection: &'a mut Connection<S>,
        visit: F,
    ) -> (Self, Option<crate::Error>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        F: FnMut(ReceivedToken),
    {
        Self::until_error_from_stream(TokenStream::new(connection).try_unfold(), visit).await
    }

    async fn until_error_from_stream<T, F>(
        mut tokens: T,
        mut visit: F,
    ) -> (Self, Option<crate::Error>)
    where
        T: Stream<Item = crate::Result<ReceivedToken>> + Unpin,
        F: FnMut(ReceivedToken),
    {
        let mut rows_affected = Vec::new();
        let mut server_error = None;

        loop {
            match tokens.try_next().await {
                Ok(Some(ReceivedToken::Error(error))) => {
                    server_error.get_or_insert(crate::Error::Server(error));
                }
                Ok(Some(
                    ReceivedToken::DoneProc(_)
                    | ReceivedToken::DoneInProc(_)
                    | ReceivedToken::Done(_),
                )) if server_error.is_some() => (),
                Ok(Some(ReceivedToken::DoneProc(done))) if done.is_final() => (),
                Ok(Some(
                    ReceivedToken::DoneProc(done)
                    | ReceivedToken::DoneInProc(done)
                    | ReceivedToken::Done(done),
                )) => rows_affected.push(done.rows()),
                Ok(Some(token)) => visit(token),
                Ok(None) => break,
                // The token stream raises its first server error again at the end.
                Err(crate::Error::Server(_)) if server_error.is_some() => break,
                Err(error) => return (Self { rows_affected }, Some(error)),
            }
        }

        (Self { rows_affected }, server_error)
    }

    /// A slice of numbers of rows affected in the same order as the given
    /// queries.
    pub fn rows_affected(&self) -> &[u64] {
        self.rows_affected.as_slice()
    }

    /// Aggregates all resulting row counts into a sum.
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
    /// let rows_affected = client
    ///     .execute(
    ///         "INSERT INTO #Test (id) VALUES (@P1); INSERT INTO #Test (id) VALUES (@P2, @P3)",
    ///         &[&1i32, &2i32, &3i32],
    ///     )
    ///     .await?;
    ///
    /// assert_eq!(3, rows_affected.total());
    /// # Ok(())
    /// # }
    pub fn total(self) -> u64 {
        self.rows_affected.into_iter().sum()
    }
}

impl IntoIterator for ExecuteResult {
    type Item = u64;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows_affected.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::{TokenDone, TokenError};
    use futures_util::stream::iter;

    fn in_proc(rows: u64) -> crate::Result<ReceivedToken> {
        Ok(ReceivedToken::DoneInProc(TokenDone::with_more_rows(rows)))
    }

    fn final_done_proc() -> crate::Result<ReceivedToken> {
        Ok(ReceivedToken::DoneProc(TokenDone::default()))
    }

    fn server_error(code: u32) -> TokenError {
        TokenError::new(code, 1, 16, "e", "srv", "", 1)
    }

    async fn read(tokens: Vec<crate::Result<ReceivedToken>>) -> (Vec<u64>, Option<crate::Error>) {
        let (result, error) = ExecuteResult::until_error_from_stream(iter(tokens), |_| ()).await;
        (result.rows_affected, error)
    }

    #[tokio::test]
    async fn until_error_visits_other_tokens_after_the_error() {
        let mut visited = Vec::new();
        let (result, error) = ExecuteResult::until_error_from_stream(
            iter(vec![
                Ok(ReceivedToken::ReturnStatus(0)),
                Ok(ReceivedToken::Error(server_error(2627))),
                in_proc(1),
                Ok(ReceivedToken::ReturnStatus(1)),
                final_done_proc(),
                Err(crate::Error::Server(server_error(2627))),
            ]),
            |token| {
                if let ReceivedToken::ReturnStatus(status) = token {
                    visited.push(status);
                }
            },
        )
        .await;
        assert!(result.rows_affected.is_empty());
        assert!(error.is_some());
        assert_eq!(visited, [0, 1]);
    }

    #[tokio::test]
    async fn until_error_returns_every_count_of_a_successful_response() {
        let (rows, error) = read(vec![in_proc(1), in_proc(0), in_proc(2), final_done_proc()]).await;
        assert_eq!(rows, [1, 0, 2]);
        assert!(error.is_none());
    }

    #[tokio::test]
    async fn until_error_keeps_counts_before_the_first_server_error() {
        let (rows, error) = read(vec![
            in_proc(1),
            in_proc(1),
            Ok(ReceivedToken::Error(server_error(2627))),
            in_proc(0),
            Ok(ReceivedToken::Error(server_error(3621))),
            in_proc(1),
            final_done_proc(),
            Err(crate::Error::Server(server_error(2627))),
        ])
        .await;
        assert_eq!(rows, [1, 1]);
        assert!(matches!(error, Some(crate::Error::Server(e)) if e.code() == 2627));
    }

    #[tokio::test]
    async fn until_error_returns_a_transport_or_cancel_error_with_earlier_counts() {
        for failure in [
            crate::Error::Canceled,
            crate::Error::Protocol("reset".into()),
        ] {
            let (rows, error) = read(vec![in_proc(1), Err(failure)]).await;
            assert_eq!(rows, [1]);
            assert!(matches!(
                error,
                Some(crate::Error::Canceled | crate::Error::Protocol(_))
            ));
        }
    }
}
