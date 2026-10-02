use std::borrow::Cow;

use byteorder::{ByteOrder, LittleEndian};

use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::Collation, VarLenType};

pub(crate) async fn decode<R>(
    src: &mut R,
    ty: VarLenType,
    len: usize,
    collation: Option<Collation>,
) -> crate::Result<Option<Cow<'static, str>>>
where
    R: SqlReadBytes + Unpin,
{
    use VarLenType::*;

    let data = super::plp::decode(src, len).await?;

    match (data, ty) {
        // Codepages other than UTF
        (Some(buf), BigChar) | (Some(buf), BigVarChar) => {
            let collation = collation.as_ref().unwrap();
            let encoder = collation.encoding()?;

            // A borrowed result means the bytes are already the UTF-8 text, so
            // keep the buffer instead of copying it.
            let transcoded =
                match encoder.decode_without_bom_handling_and_without_replacement(buf.as_ref()) {
                    Some(Cow::Owned(text)) => Some(text),
                    Some(Cow::Borrowed(_)) => None,
                    None => return Err(Error::Encoding("invalid sequence".into())),
                };
            let s = match transcoded {
                Some(text) => text,
                None => String::from_utf8(buf)
                    .map_err(|_| Error::Encoding("invalid sequence".into()))?,
            };

            Ok(Some(s.into()))
        }
        // UTF-16
        (Some(buf), _) => {
            if buf.len() % 2 != 0 {
                return Err(Error::Protocol("nvarchar: invalid plp length".into()));
            }

            let buf: Vec<_> = buf.chunks(2).map(LittleEndian::read_u16).collect();
            Ok(Some(String::from_utf16(&buf)?.into()))
        }
        _ => Ok(None),
    }
}

pub(crate) async fn decode_short<R>(
    src: &mut R,
    ty: VarLenType,
    max_len: usize,
    collation: Option<Collation>,
) -> crate::Result<Option<Cow<'static, str>>>
where
    R: SqlReadBytes + Unpin,
{
    let len = src.read_u8().await? as usize;
    if len == 0xff {
        return Ok(None);
    }

    if len > max_len {
        return Err(Error::Protocol(
            format!("varchar: length {} exceeds column limit {}", len, max_len).into(),
        ));
    }

    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(src.read_u8().await?);
    }

    match ty {
        VarLenType::Char | VarLenType::VarChar => {
            let collation = collation.ok_or_else(|| Error::Protocol("varchar: missing collation".into()))?;
            let encoder = collation.encoding()?;
            let s = encoder
                .decode_without_bom_handling_and_without_replacement(buf.as_ref())
                .ok_or_else(|| Error::Encoding("invalid sequence".into()))?
                .to_string();
            Ok(Some(s.into()))
        }
        _ => Err(Error::Protocol("varchar: unsupported type".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_read_bytes::test_utils::IntoSqlReadBytes;
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn code_page_text_keeps_ascii_and_transcodes_other_bytes() {
        let collation = Some(Collation::new(13632521, 52));
        for (bytes, expected) in [
            (&b"plain text"[..], "plain text"),
            (&b""[..], ""),
            (&[b'c', b'a', b'f', 0xe9][..], "caf\u{e9}"),
        ] {
            let mut wire = BytesMut::new();
            wire.put_u16_le(bytes.len() as u16);
            wire.put_slice(bytes);
            wire.put_u8(0xad);
            let mut reader = wire.into_sql_read_bytes();
            let value = decode(&mut reader, VarLenType::BigVarChar, 8000, collation)
                .await
                .unwrap();
            assert_eq!(value.as_deref(), Some(expected));
            assert_eq!(reader.read_u8().await.unwrap(), 0xad);
        }
    }
}
