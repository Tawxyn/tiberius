//! Error module
pub use crate::tds::codec::TokenError;
pub use std::io::ErrorKind as IoErrorKind;
use std::{borrow::Cow, convert::Infallible, io};
use thiserror::Error;

/// A unified error enum that contains several errors that might occurr during
/// the lifecycle of this driver
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    #[error("An error occured during the attempt of performing I/O: {}", message)]
    /// An error occured when performing I/O to the server.
    Io {
        /// A list specifying general categories of I/O error.
        kind: IoErrorKind,
        /// The error description.
        message: String,
    },
    #[error("Protocol error: {}", _0)]
    /// An error happened during the request or response parsing.
    Protocol(Cow<'static, str>),
    #[error("Encoding error: {}", _0)]
    /// Server responded with encoding not supported.
    Encoding(Cow<'static, str>),
    #[error("Conversion error: {}", _0)]
    /// Conversion failure from one type to another.
    Conversion(Cow<'static, str>),
    #[error("UTF-8 error")]
    /// Tried to convert data to UTF-8 that was not valid.
    Utf8,
    #[error("UTF-16 error")]
    /// Tried to convert data to UTF-16 that was not valid.
    Utf16,
    #[error("Error parsing an integer: {}", _0)]
    /// Tried to parse an integer that was not an integer.
    ParseInt(std::num::ParseIntError),
    #[error("Token error: {}", _0)]
    /// An error returned by the server.
    Server(TokenError),
    #[error("Error forming TLS connection: {}", _0)]
    /// An error in the TLS handshake.
    Tls(String),
    #[cfg(any(all(unix, feature = "integrated-auth-gssapi"), doc))]
    #[cfg_attr(
        feature = "docs",
        doc(cfg(all(unix, feature = "integrated-auth-gssapi")))
    )]
    /// An error from the GSSAPI library.
    #[error("GSSAPI Error: {}", _0)]
    Gssapi(String),
    #[error(
        "Server requested a connection to an alternative address: `{}:{}`",
        host,
        port
    )]
    /// Server requested a connection to an alternative address.
    Routing {
        /// The requested hostname
        host: String,
        /// The requested port.
        port: u16,
    },
    #[error("BULK UPLOAD input failure: {0}")]
    /// Invalid input in Bulk Upload
    BulkInput(Cow<'static, str>),
    #[error("The operation was canceled")]
    /// The in-flight operation was canceled via a
    /// [`CancellationToken`](crate::CancellationToken); a TDS attention signal
    /// was sent and the response drained. The connection remains usable.
    Canceled,
    #[error("{error}; the cleanup that followed also failed: {cleanup}")]
    /// A request failed with `error`, and the cleanup that followed it, such
    /// as releasing a prepared statement, failed with `cleanup`.
    /// [`code`](Self::code) reports `error`'s code, and
    /// [`leaves_connection_usable`](Self::leaves_connection_usable) accounts
    /// for both.
    CleanupFailed {
        /// The request's error.
        error: Box<Error>,
        /// The cleanup's error.
        cleanup: Box<Error>,
    },
}

/// The lowest severity at which SQL Server ends the connection after an error.
const FATAL_SEVERITY: u8 = 20;

impl Error {
    /// True, if the error was caused by a deadlock.
    pub fn is_deadlock(&self) -> bool {
        self.code().map(|c| c == 1205).unwrap_or(false)
    }

    /// Returns the error code, if the error originates from the
    /// server.
    pub fn code(&self) -> Option<u32> {
        match self {
            Error::Server(e) => Some(e.code()),
            Error::CleanupFailed { error, .. } => error.code(),
            _ => None,
        }
    }

    /// Whether the connection is known to be able to carry another request
    /// after a request failed with this error. When it is not, the
    /// connection should be discarded.
    ///
    /// A server error arrives in a response that is read to its end, and a
    /// cancellation ends when the server acknowledges the attention. A
    /// server error of severity 20 or higher is fatal, though, and the server
    /// ends the connection after sending it. Any other error, such as an I/O
    /// or protocol error, can stop reading in the middle of a response or a
    /// packet, so it reports `false`, even for an error the client raised
    /// without touching the connection.
    pub fn leaves_connection_usable(&self) -> bool {
        match self {
            Error::Server(error) => error.class() < FATAL_SEVERITY,
            Error::Canceled => true,
            Error::CleanupFailed { error, cleanup } => {
                error.leaves_connection_usable() && cleanup.leaves_connection_usable()
            }
            _ => false,
        }
    }

    /// Returns a request's error together with that of the cleanup that
    /// followed it: the request's error alone when the cleanup succeeded, the
    /// cleanup's when only it failed, and [`CleanupFailed`](Self::CleanupFailed)
    /// when both did.
    pub(crate) fn with_cleanup(error: Option<Error>, cleanup: crate::Result<()>) -> Option<Error> {
        match (error, cleanup) {
            (error, Ok(())) => error,
            (None, Err(cleanup)) => Some(cleanup),
            (Some(error), Err(cleanup)) => Some(Error::CleanupFailed {
                error: Box::new(error),
                cleanup: Box::new(cleanup),
            }),
        }
    }
}

impl From<uuid::Error> for Error {
    fn from(e: uuid::Error) -> Self {
        Self::Conversion(format!("Error convertiong a Guid value {}", e).into())
    }
}

#[cfg(feature = "native-tls")]
impl From<async_native_tls::Error> for Error {
    fn from(v: async_native_tls::Error) -> Self {
        Error::Tls(format!("{}", v))
    }
}

#[cfg(feature = "vendored-openssl")]
impl From<opentls::Error> for Error {
    fn from(v: opentls::Error) -> Self {
        Error::Tls(format!("{}", v))
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Self::Io {
            kind: err.kind(),
            message: format!("{}", err),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Error {
        Error::ParseInt(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Error {
        Error::Utf8
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(_err: std::string::FromUtf8Error) -> Error {
        Error::Utf8
    }
}

impl From<std::string::FromUtf16Error> for Error {
    fn from(_err: std::string::FromUtf16Error) -> Error {
        Error::Utf16
    }
}

impl From<connection_string::Error> for Error {
    fn from(err: connection_string::Error) -> Error {
        let err = Cow::Owned(format!("{}", err));
        Error::Conversion(err)
    }
}

#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
#[cfg_attr(
    feature = "docs",
    doc(cfg(all(unix, feature = "integrated-auth-gssapi")))
)]
impl From<libgssapi::error::Error> for Error {
    fn from(err: libgssapi::error::Error) -> Error {
        Error::Gssapi(format!("{}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_error(code: u32) -> Error {
        Error::Server(TokenError::new(code, 1, 16, "e", "srv", "", 1))
    }

    fn broken_pipe() -> Error {
        Error::Io {
            kind: IoErrorKind::BrokenPipe,
            message: "broken pipe".into(),
        }
    }

    #[test]
    fn with_cleanup_keeps_a_cleanup_failure_alongside_the_request_error() {
        assert_eq!(Error::with_cleanup(None, Ok(())), None);
        assert_eq!(
            Error::with_cleanup(Some(server_error(2627)), Ok(())),
            Some(server_error(2627))
        );
        assert_eq!(
            Error::with_cleanup(None, Err(broken_pipe())),
            Some(broken_pipe())
        );
        assert_eq!(
            Error::with_cleanup(Some(server_error(2627)), Err(broken_pipe())),
            Some(Error::CleanupFailed {
                error: Box::new(server_error(2627)),
                cleanup: Box::new(broken_pipe()),
            })
        );
    }

    #[test]
    fn cleanup_failure_reports_the_request_code_and_both_connection_states() {
        let failed = |error, cleanup| Error::CleanupFailed {
            error: Box::new(error),
            cleanup: Box::new(cleanup),
        };

        let after_io = failed(server_error(2627), broken_pipe());
        assert_eq!(after_io.code(), Some(2627));
        assert!(!after_io.leaves_connection_usable());

        let after_server_error = failed(server_error(2627), server_error(8179));
        assert_eq!(after_server_error.code(), Some(2627));
        assert!(after_server_error.leaves_connection_usable());

        assert!(
            !failed(Error::Canceled, Error::Protocol("bad token".into()))
                .leaves_connection_usable()
        );
        assert!(failed(Error::Canceled, Error::Canceled).leaves_connection_usable());

        let after_fatal = failed(server_error(2627), server_error_of_severity(20));
        assert_eq!(after_fatal.code(), Some(2627));
        assert!(!after_fatal.leaves_connection_usable());
    }

    fn server_error_of_severity(class: u8) -> Error {
        Error::Server(TokenError::new(50000, 1, class, "e", "srv", "", 1))
    }

    #[test]
    fn a_fatal_server_error_leaves_the_connection_unusable() {
        assert!(server_error_of_severity(19).leaves_connection_usable());
        assert!(!server_error_of_severity(20).leaves_connection_usable());
        assert!(!server_error_of_severity(25).leaves_connection_usable());
    }
}
