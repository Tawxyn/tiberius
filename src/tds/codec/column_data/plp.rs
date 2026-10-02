use crate::sql_read_bytes::SqlReadBytes;
use futures_util::io::AsyncReadExt;

// Decode a partially length-prefixed type.
pub(crate) async fn decode<R>(src: &mut R, len: usize) -> crate::Result<Option<Vec<u8>>>
where
    R: SqlReadBytes + Unpin,
{
    match len {
        // Fixed size
        len if len < 0xffff => {
            let len = src.read_u16_le().await? as u64;

            match len {
                // NULL
                0xffff => Ok(None),
                _ => {
                    let mut data = vec![0; len as usize];
                    src.read_exact(&mut data).await?;

                    Ok(Some(data))
                }
            }
        }
        // Unknown size, length-prefixed blobs
        _ => decode_unknown_size(src).await,
    }
}

/// Decode a value that is always PLP-encoded, for types whose `MAX_LEN` does
/// not select the wire format the way [`decode`] assumes (notably UDTs).
pub(crate) async fn decode_unknown_size<R>(src: &mut R) -> crate::Result<Option<Vec<u8>>>
where
    R: SqlReadBytes + Unpin,
{
    let len = src.read_u64_le().await?;

    let mut data = match len {
        // NULL
        0xffffffffffffffff => return Ok(None),
        // Unknown size
        0xfffffffffffffffe => Vec::new(),
        // Known size
        _ => Vec::with_capacity(len as usize),
    };

    loop {
        let mut chunk_data_left = src.read_u32_le().await? as usize;
        if chunk_data_left == 0 {
            break;
        }
        while chunk_data_left > 0 {
            // Limit each read so the connection need not accumulate a whole
            // MAX value's chunk before the decoder can make progress.
            let read_len = chunk_data_left.min(8192);
            let start = data.len();
            data.resize(start + read_len, 0);
            src.read_exact(&mut data[start..]).await?;
            chunk_data_left -= read_len;
        }
    }

    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::Context;
    use futures_util::io::{AsyncRead, Cursor};
    use std::{io, pin::Pin, task};

    struct FragmentedReader {
        inner: Cursor<Vec<u8>>,
        pending: bool,
        largest_read: usize,
        context: Context,
    }

    impl FragmentedReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(data),
                pending: true,
                largest_read: 0,
                context: Context::new(),
            }
        }
    }

    impl AsyncRead for FragmentedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut task::Context<'_>,
            output: &mut [u8],
        ) -> task::Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.largest_read = this.largest_read.max(output.len());
            if this.pending {
                this.pending = false;
                cx.waker().wake_by_ref();
                return task::Poll::Pending;
            }
            this.pending = true;
            let count = output.len().min(7);
            Pin::new(&mut this.inner).poll_read(cx, &mut output[..count])
        }
    }

    impl SqlReadBytes for FragmentedReader {
        fn debug_buffer(&self) {}

        fn context(&self) -> &Context {
            &self.context
        }

        fn context_mut(&mut self) -> &mut Context {
            &mut self.context
        }
    }

    #[tokio::test]
    async fn fixed_values_survive_fragmentation_without_consuming_next_token() {
        for value in [
            None,
            Some(Vec::new()),
            Some(vec![0, 1, 2, 0xff, 0, 7, 8, 9]),
        ] {
            let length = value.as_ref().map_or(0xffff, |value| value.len() as u16);
            let mut wire = length.to_le_bytes().to_vec();
            if let Some(value) = value.as_ref() {
                wire.extend(value);
            }
            wire.push(0xad);
            let mut reader = FragmentedReader::new(wire);
            assert_eq!(decode(&mut reader, 8000).await.unwrap(), value);
            assert_eq!(reader.read_u8().await.unwrap(), 0xad);
        }
    }

    #[tokio::test]
    async fn max_values_survive_multiple_chunks_and_pending_reads() {
        let payload = (0..9017)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        for length in [payload.len() as u64, 0xfffffffffffffffe] {
            let mut wire = length.to_le_bytes().to_vec();
            for chunk in [&payload[..9000], &payload[9000..]] {
                wire.extend((chunk.len() as u32).to_le_bytes());
                wire.extend(chunk);
            }
            wire.extend(0u32.to_le_bytes());
            wire.push(0xad);
            let mut reader = FragmentedReader::new(wire);
            assert_eq!(
                decode(&mut reader, 0xffff).await.unwrap(),
                Some(payload.clone())
            );
            assert!(reader.largest_read <= 8192);
            assert_eq!(reader.read_u8().await.unwrap(), 0xad);
        }
    }

    #[tokio::test]
    async fn max_null_and_empty_leave_next_token_intact() {
        for length in [0xffffffffffffffffu64, 0, 0xfffffffffffffffe] {
            let mut wire = length.to_le_bytes().to_vec();
            if length != 0xffffffffffffffff {
                wire.extend(0u32.to_le_bytes());
            }
            wire.push(0xad);
            let mut reader = FragmentedReader::new(wire);
            let expected = if length == 0xffffffffffffffff {
                None
            } else {
                Some(Vec::new())
            };
            assert_eq!(decode(&mut reader, 0xffff).await.unwrap(), expected);
            assert_eq!(reader.read_u8().await.unwrap(), 0xad);
        }
    }

    #[tokio::test]
    async fn truncated_fixed_and_max_payloads_fail() {
        let mut reader = FragmentedReader::new(vec![3, 0, 1, 2]);
        assert!(decode(&mut reader, 8000).await.is_err());

        let mut wire = 0xfffffffffffffffeu64.to_le_bytes().to_vec();
        wire.extend(4u32.to_le_bytes());
        wire.extend([1, 2, 3]);
        let mut reader = FragmentedReader::new(wire);
        assert!(decode(&mut reader, 0xffff).await.is_err());
    }
}
