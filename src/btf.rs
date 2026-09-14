//! Asking the kernel where its own fields are.
//!
//! The eBPF program needs to read a few fields out of `struct sock`, and the
//! byte offset of each one differs between kernel builds — a config option
//! flipped, a different version, a distro patch, and the field moves. A
//! program compiled with offsets baked in reads whatever now lives at the old
//! address and reports it confidently, which is the worst kind of wrong: there
//! is no error, just numbers that are not the numbers.
//!
//! The kernel publishes its own layout at `/sys/kernel/btf/vmlinux`, so the
//! offsets are looked up there at startup, on the machine the program is about
//! to run on, and handed to it. This is the same idea as libbpf's CO-RE, done
//! by hand and only as far as it needs to go: this reads offsets, and nothing
//! else about BTF is implemented.
//!
//! The format is in the kernel's `Documentation/bpf/btf.rst`. Only what is
//! needed to walk a struct is parsed here.

use std::collections::HashMap;

const MAGIC: u16 = 0xeb9f;

// The kinds this needs to recognise. The rest are skipped by length.
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;
const KIND_INT: u32 = 1;

#[derive(Debug, Clone)]
struct Member {
    name: String,
    type_id: u32,
    /// Offset from the start of the containing struct, in bits.
    bit_offset: u32,
}

#[derive(Debug, Clone)]
struct Type {
    name: String,
    kind: u32,
    /// For a typedef or qualifier, what it refers to.
    referent: u32,
    members: Vec<Member>,
}

pub struct Btf {
    types: Vec<Type>,
    /// Name to id, for composite types only — the only ones looked up by name.
    by_name: HashMap<String, u32>,
}

impl Btf {
    /// Read the running kernel's own type information.
    pub fn from_running_kernel() -> Result<Self, String> {
        const PATH: &str = "/sys/kernel/btf/vmlinux";
        let raw = std::fs::read(PATH).map_err(|e| {
            format!(
                "could not read {PATH}: {e}\n\n\
                 netwatch needs the kernel's own type information to find the \
                 fields it reads. A kernel built with CONFIG_DEBUG_INFO_BTF \
                 provides it; every current distribution enables that."
            )
        })?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let r = Reader::new(raw);

        // ── header ──────────────────────────────────────────────────────────
        let magic = r.u16(0)?;
        if magic != MAGIC {
            return Err(format!(
                "not BTF: expected magic {MAGIC:#06x}, found {magic:#06x}"
            ));
        }
        let hdr_len = r.u32(4)?;
        let type_off = r.u32(8)? as usize;
        let type_len = r.u32(12)? as usize;
        let str_off = r.u32(16)? as usize;
        let str_len = r.u32(20)? as usize;

        // The two sections are placed relative to the end of the header, not
        // to the start of the file.
        let base = hdr_len as usize;
        let types_start = base
            .checked_add(type_off)
            .ok_or("BTF type section offset overflows")?;
        let types_end = types_start
            .checked_add(type_len)
            .ok_or("BTF type section length overflows")?;
        let strs_start = base
            .checked_add(str_off)
            .ok_or("BTF string section offset overflows")?;
        let strs_end = strs_start
            .checked_add(str_len)
            .ok_or("BTF string section length overflows")?;
        if types_end > raw.len() || strs_end > raw.len() {
            return Err("BTF sections run past the end of the data".into());
        }
        let strings = &raw[strs_start..strs_end];

        // ── types ───────────────────────────────────────────────────────────
        // Type ids start at 1; id 0 is void, which has no entry.
        let mut types = vec![Type {
            name: String::new(),
            kind: 0,
            referent: 0,
            members: Vec::new(),
        }];
        let mut by_name = HashMap::new();

        let mut at = types_start;
        while at < types_end {
            let name_off = r.u32(at)?;
            let info = r.u32(at + 4)?;
            let size_or_type = r.u32(at + 8)?;
            at += 12;

            let vlen = info & 0xffff;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = (info >> 31) & 1 == 1;

            let name = string_at(strings, name_off)?;
            let mut members = Vec::new();

            match kind {
                KIND_STRUCT | KIND_UNION => {
                    for _ in 0..vlen {
                        let m_name = string_at(strings, r.u32(at)?)?;
                        let m_type = r.u32(at + 4)?;
                        let raw_offset = r.u32(at + 8)?;
                        at += 12;
                        // With the kind flag set, the low 24 bits are the bit
                        // offset and the top 8 are a bitfield width. Without
                        // it, the whole word is the bit offset.
                        let bit_offset = if kind_flag {
                            raw_offset & 0x00ff_ffff
                        } else {
                            raw_offset
                        };
                        members.push(Member {
                            name: m_name,
                            type_id: m_type,
                            bit_offset,
                        });
                    }
                }
                // Everything else is skipped by however much trailing data its
                // kind carries. Getting this wrong desynchronises the whole
                // walk, so each is stated rather than guessed.
                KIND_INT | KIND_VAR | KIND_DECL_TAG => at += 4,
                KIND_ARRAY => at += 12,
                KIND_ENUM => at += 8 * vlen as usize,
                KIND_ENUM64 => at += 12 * vlen as usize,
                KIND_FUNC_PROTO => at += 8 * vlen as usize,
                KIND_DATASEC => at += 12 * vlen as usize,
                _ => {}
            }

            let id = types.len() as u32;
            if !name.is_empty() && (kind == KIND_STRUCT || kind == KIND_UNION) {
                // Forward declarations and duplicates exist; the first
                // definition with members is the one worth keeping.
                by_name.entry(name.clone()).or_insert(id);
            }
            types.push(Type {
                name,
                kind,
                referent: size_or_type,
                members,
            });
        }

        Ok(Self { types, by_name })
    }

    /// The byte offset of a field, named as a path from a struct: the offset
    /// of `skc_daddr` within `sock` is `offset_of("sock", &["__sk_common",
    /// "skc_daddr"])`.
    ///
    /// Anonymous members are descended into transparently, because that is how
    /// C reads them: a field inside an unnamed union belongs to the struct
    /// containing it, and `struct sock_common` keeps several of the fields
    /// wanted here inside exactly such a union.
    pub fn offset_of(&self, struct_name: &str, path: &[&str]) -> Result<u32, String> {
        let mut id = *self
            .by_name
            .get(struct_name)
            .ok_or_else(|| format!("this kernel's BTF has no struct {struct_name}"))?;
        let mut bits = 0u32;

        for field in path {
            let ty = self.resolve(id)?;
            let (found, at) = self
                .find_member(ty, field)
                .ok_or_else(|| format!("struct {} has no field {field}", ty.name))?;
            bits += at;
            id = found;
        }
        Ok(bits / 8)
    }

    /// Look for a field by name, descending into anonymous members, and return
    /// its type together with its bit offset from where the search started.
    fn find_member(&self, ty: &Type, field: &str) -> Option<(u32, u32)> {
        for m in &ty.members {
            if m.name == field {
                return Some((m.type_id, m.bit_offset));
            }
            if m.name.is_empty() {
                // An unnamed struct or union: its fields are the parent's.
                if let Ok(inner) = self.resolve(m.type_id)
                    && (inner.kind == KIND_STRUCT || inner.kind == KIND_UNION)
                    && let Some((id, at)) = self.find_member(inner, field)
                {
                    return Some((id, m.bit_offset + at));
                }
            }
        }
        None
    }

    /// Follow typedefs, qualifiers and pointers to the thing underneath. A
    /// field declared `const struct foo *` is still a `struct foo` for the
    /// purpose of finding what is inside it.
    fn resolve(&self, mut id: u32) -> Result<&Type, String> {
        // Bounded rather than a `loop`: malformed BTF could otherwise point a
        // typedef at itself and hang the program at startup.
        for _ in 0..16 {
            let ty = self
                .types
                .get(id as usize)
                .ok_or_else(|| format!("BTF type id {id} is out of range"))?;
            match ty.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_PTR
                | KIND_TYPE_TAG => id = ty.referent,
                _ => return Ok(ty),
            }
        }
        Err("BTF type chain is circular or absurdly deep".into())
    }
}

fn string_at(strings: &[u8], off: u32) -> Result<String, String> {
    let start = off as usize;
    if start >= strings.len() {
        // An offset past the table is not fatal: it names nothing, and an
        // unnamed type is a perfectly ordinary thing to meet.
        return Ok(String::new());
    }
    let end = strings[start..]
        .iter()
        .position(|b| *b == 0)
        .map(|n| start + n)
        .unwrap_or(strings.len());
    Ok(String::from_utf8_lossy(&strings[start..end]).into_owned())
}

/// Bounds-checked little-endian reads. BTF written by a big-endian kernel
/// would need byte-swapping, which is not implemented: netwatch's eBPF support
/// is built for x86_64 and aarch64, both little-endian.
struct Reader<'a> {
    raw: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    fn u16(&self, at: usize) -> Result<u16, String> {
        let b = self
            .raw
            .get(at..at + 2)
            .ok_or_else(|| format!("BTF ends before offset {at}"))?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, at: usize) -> Result<u32, String> {
        let b = self
            .raw
            .get(at..at + 4)
            .ok_or_else(|| format!("BTF ends before offset {at}"))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A builder for synthetic BTF, so the parser can be tested against a
    /// known layout without needing a particular kernel to be running.
    #[derive(Default)]
    struct Build {
        types: Vec<u8>,
        strings: Vec<u8>,
    }

    impl Build {
        fn new() -> Self {
            // The string table always starts with an empty string at 0, which
            // is how "unnamed" is spelled.
            Self {
                types: Vec::new(),
                strings: vec![0],
            }
        }

        fn name(&mut self, s: &str) -> u32 {
            let at = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            at
        }

        fn int(&mut self, s: &str, bytes: u32) -> u32 {
            let n = self.name(s);
            self.types.extend_from_slice(&n.to_le_bytes());
            self.types
                .extend_from_slice(&(KIND_INT << 24).to_le_bytes());
            self.types.extend_from_slice(&bytes.to_le_bytes());
            self.types.extend_from_slice(&0u32.to_le_bytes()); // int encoding
            self.next_id()
        }

        /// `members` are (name, type id, bit offset).
        fn composite(
            &mut self,
            kind: u32,
            s: &str,
            size: u32,
            members: &[(&str, u32, u32)],
        ) -> u32 {
            let n = self.name(s);
            let info = (kind << 24) | members.len() as u32;
            self.types.extend_from_slice(&n.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size.to_le_bytes());
            for (mn, mt, mo) in members {
                let mn = self.name(mn);
                self.types.extend_from_slice(&mn.to_le_bytes());
                self.types.extend_from_slice(&mt.to_le_bytes());
                self.types.extend_from_slice(&mo.to_le_bytes());
            }
            self.next_id()
        }

        /// How many types have been written; ids start at 1.
        fn next_id(&self) -> u32 {
            let mut id = 0;
            let mut at = 0;
            while at < self.types.len() {
                let info = u32::from_le_bytes(self.types[at + 4..at + 8].try_into().unwrap());
                let vlen = info & 0xffff;
                let kind = (info >> 24) & 0x1f;
                at += 12;
                match kind {
                    KIND_INT => at += 4,
                    KIND_STRUCT | KIND_UNION => at += 12 * vlen as usize,
                    _ => {}
                }
                id += 1;
            }
            id
        }

        fn finish(self) -> Vec<u8> {
            let hdr_len = 24u32;
            let mut out = Vec::new();
            out.extend_from_slice(&MAGIC.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&hdr_len.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// The shape that matters: a field reached through a named inner struct,
    /// which is how `sock.__sk_common.skc_family` is reached.
    #[test]
    fn a_field_in_a_nested_struct_is_found() {
        let mut b = Build::new();
        let u16t = b.int("short unsigned int", 2);
        let u32t = b.int("unsigned int", 4);

        let common = b.composite(
            KIND_STRUCT,
            "sock_common",
            16,
            &[("skc_daddr", u32t, 0), ("skc_family", u16t, 64)],
        );
        b.composite(
            KIND_STRUCT,
            "sock",
            64,
            &[("__sk_common", common, 0), ("sk_err", u32t, 256)],
        );

        let btf = Btf::parse(&b.finish()).expect("parse");
        assert_eq!(btf.offset_of("sock", &["__sk_common", "skc_daddr"]), Ok(0));
        assert_eq!(btf.offset_of("sock", &["__sk_common", "skc_family"]), Ok(8));
        assert_eq!(btf.offset_of("sock", &["sk_err"]), Ok(32));
    }

    /// `struct sock_common` keeps several of the fields netwatch reads inside
    /// an unnamed union. A parser that did not descend into it would report
    /// the field as missing, on every kernel.
    #[test]
    fn a_field_inside_an_anonymous_union_belongs_to_its_parent() {
        let mut b = Build::new();
        let u32t = b.int("unsigned int", 4);

        // union { struct { u32 skc_daddr; u32 skc_rcv_saddr; }; };
        let pair = b.composite(
            KIND_STRUCT,
            "",
            8,
            &[("skc_daddr", u32t, 0), ("skc_rcv_saddr", u32t, 32)],
        );
        let anon_union = b.composite(KIND_UNION, "", 8, &[("", pair, 0)]);
        b.composite(
            KIND_STRUCT,
            "sock_common",
            16,
            &[("skc_hash", u32t, 0), ("", anon_union, 64)],
        );

        let btf = Btf::parse(&b.finish()).expect("parse");
        assert_eq!(btf.offset_of("sock_common", &["skc_daddr"]), Ok(8));
        assert_eq!(btf.offset_of("sock_common", &["skc_rcv_saddr"]), Ok(12));
    }

    /// A field that is not there must say so. Reading a guessed offset would
    /// return a number rather than an error, and nothing downstream could tell
    /// the difference.
    #[test]
    fn a_missing_field_is_an_error_not_a_guess() {
        let mut b = Build::new();
        let u32t = b.int("unsigned int", 4);
        b.composite(KIND_STRUCT, "sock", 8, &[("sk_err", u32t, 0)]);

        let btf = Btf::parse(&b.finish()).expect("parse");
        assert!(btf.offset_of("sock", &["skc_daddr"]).is_err());
        assert!(btf.offset_of("nonexistent", &["x"]).is_err());
    }

    /// The real thing: on a machine that publishes BTF, every field netwatch
    /// reads must be findable. This is what would catch a kernel that renamed
    /// or moved one of them — which is the whole reason the offsets are looked
    /// up rather than assumed.
    ///
    /// Skipped where there is no BTF to read, since that is a property of the
    /// machine and not a fault in this code.
    #[test]
    fn the_fields_netwatch_reads_exist_on_this_kernel() {
        let Ok(btf) = Btf::from_running_kernel() else {
            return;
        };
        for field in ["skc_family", "skc_daddr", "skc_dport", "skc_v6_daddr"] {
            let at = btf.offset_of("sock", &["__sk_common", field]);
            assert!(at.is_ok(), "sock.__sk_common.{field}: {at:?}");
            println!("sock.__sk_common.{field} is at byte {}", at.unwrap());
        }
    }

    #[test]
    fn something_that_is_not_btf_is_refused() {
        assert!(Btf::parse(b"not btf at all").is_err());
        assert!(Btf::parse(&[]).is_err());
    }
}
