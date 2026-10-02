use super::{AllHeaderTy, Encode, ALL_HEADERS_LEN_TX};
use bytes::{BufMut, BytesMut};

/// How a [`TransactionRequest`] ends the session's transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransactionOutcome {
    Commit,
    Rollback,
}

/// A transaction manager request (MS-TDS 2.2.6.9) that commits or rolls back
/// the transaction named by its descriptor, without a SQL batch to compile.
/// It starts no transaction afterwards, so a session with implicit
/// transactions on begins its next one with its next statement.
pub(crate) struct TransactionRequest {
    outcome: TransactionOutcome,
    transaction_descriptor: [u8; 8],
}

impl TransactionRequest {
    pub(crate) fn new(outcome: TransactionOutcome, transaction_descriptor: [u8; 8]) -> Self {
        Self {
            outcome,
            transaction_descriptor,
        }
    }
}

const TM_COMMIT_XACT: u16 = 7;
const TM_ROLLBACK_XACT: u16 = 8;

impl Encode<BytesMut> for TransactionRequest {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
        dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);
        dst.put_slice(&self.transaction_descriptor);
        dst.put_u32_le(1);

        dst.put_u16_le(match self.outcome {
            TransactionOutcome::Commit => TM_COMMIT_XACT,
            TransactionOutcome::Rollback => TM_ROLLBACK_XACT,
        });
        // An empty transaction name, then fBeginXact = 0.
        dst.put_u8(0);
        dst.put_u8(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_rollback_name_the_descriptor_and_begin_nothing() {
        let descriptor = [1, 2, 3, 4, 5, 6, 7, 8];
        for (outcome, request_type) in [
            (TransactionOutcome::Commit, TM_COMMIT_XACT),
            (TransactionOutcome::Rollback, TM_ROLLBACK_XACT),
        ] {
            let mut dst = BytesMut::new();
            TransactionRequest::new(outcome, descriptor)
                .encode(&mut dst)
                .unwrap();

            let mut expected = Vec::new();
            expected.extend_from_slice(&(ALL_HEADERS_LEN_TX as u32).to_le_bytes());
            expected.extend_from_slice(&(ALL_HEADERS_LEN_TX as u32 - 4).to_le_bytes());
            expected.extend_from_slice(&(AllHeaderTy::TransactionDescriptor as u16).to_le_bytes());
            expected.extend_from_slice(&descriptor);
            expected.extend_from_slice(&1u32.to_le_bytes());
            expected.extend_from_slice(&request_type.to_le_bytes());
            expected.extend_from_slice(&[0, 0]);
            assert_eq!(&dst[..], &expected[..]);
        }
    }
}
