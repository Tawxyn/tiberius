use super::{AllHeaderTy, Encode, ALL_HEADERS_LEN_TX};
use crate::{tds::codec::ColumnData, BytesMutWithTypeInfo, Result, TypeInfo};
use bytes::{BufMut, BytesMut};
use enumflags2::{bitflags, BitFlags};
use std::borrow::Cow;

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpcStatus {
    ByRefValue = 1 << 0,
    DefaultValue = 1 << 1,
    // reserved
    Encrypted = 1 << 3,
}

#[bitflags]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpcOption {
    WithRecomp = 1 << 0,
    NoMeta = 1 << 1,
    ReuseMeta = 1 << 2,
}

#[derive(Debug)]
pub struct TokenRpcRequest<'a> {
    proc_id: RpcProcIdValue<'a>,
    flags: BitFlags<RpcOption>,
    params: Vec<RpcParam<'a>>,
    transaction_desc: [u8; 8],
}

impl<'a> TokenRpcRequest<'a> {
    pub fn new<I>(proc_id: I, params: Vec<RpcParam<'a>>, transaction_desc: [u8; 8]) -> Self
    where
        I: Into<RpcProcIdValue<'a>>,
    {
        Self {
            proc_id: proc_id.into(),
            flags: BitFlags::empty(),
            params,
            transaction_desc,
        }
    }
}

#[derive(Debug)]
pub struct RpcParam<'a> {
    pub name: Cow<'a, str>,
    pub flags: BitFlags<RpcStatus>,
    /// Explicit wire type for `value`. When `None`, `value` self-describes
    /// its own type, which cannot express a nullable type for a `NULL`
    /// output placeholder.
    pub type_info: Option<TypeInfo>,
    pub value: ColumnData<'a>,
}

/// 2.2.6.6 RPC Request
#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcProcId {
    CursorOpen = 2,
    CursorPrepExec = 5,
    CursorUnprepare = 6,
    CursorFetch = 7,
    CursorClose = 9,
    ExecuteSQL = 10,
    Prepare = 11,
    Execute = 12,
    PrepExec = 13,
    Unprepare = 15,
}

/// The RPC procedure being invoked: either one of the well-known system
/// procedures by numeric id, or an arbitrary stored procedure by name.
#[derive(Debug)]
#[allow(dead_code)]
pub enum RpcProcIdValue<'a> {
    /// Call a stored procedure by name (`sp_executesql`, a user-defined
    /// procedure, etc.).
    Name(Cow<'a, str>),
    /// Call one of the well-known system procedures by its numeric id.
    Id(RpcProcId),
}

impl<'a, S> From<S> for RpcProcIdValue<'a>
where
    S: Into<Cow<'a, str>>,
{
    fn from(s: S) -> Self {
        Self::Name(s.into())
    }
}

impl<'a> From<RpcProcId> for RpcProcIdValue<'a> {
    fn from(id: RpcProcId) -> Self {
        Self::Id(id)
    }
}

impl<'a> Encode<BytesMut> for TokenRpcRequest<'a> {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32);
        dst.put_u32_le(ALL_HEADERS_LEN_TX as u32 - 4);
        dst.put_u16_le(AllHeaderTy::TransactionDescriptor as u16);
        dst.put_slice(&self.transaction_desc);
        dst.put_u32_le(1);

        match self.proc_id {
            RpcProcIdValue::Id(ref id) => {
                let val = (0xffff_u32) | ((*id as u16) as u32) << 16;
                dst.put_u32_le(val);
            }
            RpcProcIdValue::Name(ref name) => {
                // NameLenProcID.NameLen: u16 length in UCS-2 code units.
                // A value of 0xFFFF signals "by ID"; anything else is the
                // length of the following UTF-16 LE procedure name.
                let codepoints: Vec<u16> = name.encode_utf16().collect();
                if codepoints.len() > u16::MAX as usize - 1 {
                    return Err(crate::Error::Protocol(
                        format!(
                            "RPC proc name too long ({} code units, max {})",
                            codepoints.len(),
                            u16::MAX - 1
                        )
                        .into(),
                    ));
                }
                dst.put_u16_le(codepoints.len() as u16);
                for cp in codepoints {
                    dst.put_u16_le(cp);
                }
            }
        }

        dst.put_u16_le(self.flags.bits());

        for param in self.params.into_iter() {
            param.encode(dst)?;
        }

        Ok(())
    }
}

impl<'a> Encode<BytesMut> for RpcParam<'a> {
    fn encode(self, dst: &mut BytesMut) -> Result<()> {
        // ParamMetaData.ParamName is a B_VARCHAR: a u8 length in UCS-2 code
        // units, so a longer name cannot be represented on the wire.
        let name_len = self.name.encode_utf16().count();
        if name_len > u8::MAX as usize {
            return Err(crate::Error::Protocol(
                format!(
                    "RPC param name too long ({} code units, max {})",
                    name_len,
                    u8::MAX
                )
                .into(),
            ));
        }

        dst.put_u8(name_len as u8);

        for codepoint in self.name.encode_utf16() {
            dst.put_u16_le(codepoint);
        }

        dst.put_u8(self.flags.bits());

        match self.type_info {
            Some(ty) => {
                // No preceding metadata token carries TYPE_INFO for an RPC
                // param, so write the header before the value.
                ty.clone().encode(dst)?;
                let mut dst_fi = BytesMutWithTypeInfo::new(dst).with_type_info(&ty);
                self.value.encode(&mut dst_fi)?;
            }
            None => {
                let mut dst_fi = BytesMutWithTypeInfo::new(dst);
                self.value.encode(&mut dst_fi)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_proc_id_uses_ffff_sentinel() {
        let req = TokenRpcRequest::new(RpcProcId::ExecuteSQL, Vec::new(), [0; 8]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let proc_id_word = &buf[ALL_HEADERS_LEN_TX..ALL_HEADERS_LEN_TX + 4];
        assert_eq!(
            proc_id_word,
            &[0xff, 0xff, RpcProcId::ExecuteSQL as u8, 0x00]
        );
    }

    #[test]
    fn encode_param_with_explicit_type_info_overrides_self_describe() {
        // A NULL i32 output placeholder with an explicit nullable
        // VarLenSized(Intn) type must encode as that type (length byte 0),
        // not the non-nullable FixedLen(Int4) the bare value would
        // self-describe as.
        use crate::tds::codec::{VarLenContext, VarLenType};

        let param = RpcParam {
            name: Cow::Borrowed(""),
            flags: RpcStatus::ByRefValue.into(),
            type_info: Some(TypeInfo::VarLenSized(VarLenContext::new(
                VarLenType::Intn,
                4,
                None,
            ))),
            value: ColumnData::I32(None),
        };
        let mut buf = BytesMut::new();
        param.encode(&mut buf).unwrap();

        // name_len(0) + status(1) + [VarLenType::Intn, max_len=4, actual_len=0]
        assert_eq!(
            &buf[..],
            &[0, RpcStatus::ByRefValue as u8, VarLenType::Intn as u8, 4, 0]
        );
    }

    #[test]
    fn encode_named_proc_writes_utf16_length_prefixed() {
        let req = TokenRpcRequest::new(Cow::Borrowed("my_sp"), Vec::new(), [0; 8]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let start = ALL_HEADERS_LEN_TX;
        let name_len = u16::from_le_bytes([buf[start], buf[start + 1]]);
        assert_eq!(name_len, 5);

        let chars_start = start + 2;
        let mut got = Vec::<u16>::new();
        for i in 0..(name_len as usize) {
            got.push(u16::from_le_bytes([
                buf[chars_start + i * 2],
                buf[chars_start + i * 2 + 1],
            ]));
        }
        let expected: Vec<u16> = "my_sp".encode_utf16().collect();
        assert_eq!(got, expected);

        // Flags follow the name.
        let flags_off = chars_start + name_len as usize * 2;
        assert_eq!(u16::from_le_bytes([buf[flags_off], buf[flags_off + 1]]), 0);
    }

    #[test]
    fn encode_named_proc_handles_non_ascii() {
        let req = TokenRpcRequest::new(Cow::Borrowed("spö"), Vec::new(), [0; 8]);
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();

        let start = ALL_HEADERS_LEN_TX;
        let name_len = u16::from_le_bytes([buf[start], buf[start + 1]]);
        let expected: Vec<u16> = "spö".encode_utf16().collect();
        assert_eq!(name_len as usize, expected.len());
    }

    fn param(name: &str) -> RpcParam<'_> {
        RpcParam {
            name: Cow::Borrowed(name),
            flags: BitFlags::empty(),
            type_info: None,
            value: ColumnData::I32(None),
        }
    }

    #[test]
    fn encode_param_name_at_the_length_limit() {
        let name = "a".repeat(u8::MAX as usize);
        let mut buf = BytesMut::new();
        param(&name).encode(&mut buf).unwrap();

        assert_eq!(buf[0], u8::MAX);
    }

    #[test]
    fn encode_param_name_over_the_length_limit_errors() {
        // 256 code units do not fit the u8 ParamName length prefix.
        let name = "a".repeat(u8::MAX as usize + 1);
        let mut buf = BytesMut::new();

        assert!(param(&name).encode(&mut buf).is_err());
    }

    #[test]
    fn encode_param_name_length_counts_utf16_code_units() {
        // A non-BMP char is two UTF-16 code units, so 128 of them are exactly
        // 256 units and must be rejected even though the name is 128 chars.
        let name = "😀".repeat(128);
        let mut buf = BytesMut::new();

        assert_eq!(name.chars().count(), 128);
        assert!(param(&name).encode(&mut buf).is_err());
    }
}
