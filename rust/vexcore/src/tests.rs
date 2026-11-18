//! Tests for the lookups.
//!
//! Run on the build host with `cargo test`, which is also why the crate is
//! built with `std` here and without it everywhere else.
//!
//! The tables are synthetic: the point is not to parse a real file, it is to
//! pin down what the two lookups answer for the shapes a file can hand them -
//! a name the filter excludes, a name the bucket holds but the chain does not,
//! a name offset that points past its own string table. Those are the cases
//! the C versions answered with a paragraph of hand-written checks, and the
//! cases a device only ever shows as "the module did not load".

use core::ffi::CStr;

use crate::hash::{vexcore_elf_hash, vexcore_gnu_hash};
use crate::lookup::{vexcore_elf_lookup, vexcore_gnu_lookup, Elf64Sym};

/// Appends `name` NUL-terminated and answers its offset, which is how a string
/// table is built.
fn push(table: &mut Vec<u8>, name: &[u8]) -> u32 {
    let offset = table.len() as u32;
    table.extend_from_slice(name);
    table.push(0);

    offset
}

/// A defined function symbol, the only kind either test needs.
fn function(st_name: u32, st_value: u64) -> Elf64Sym {
    Elf64Sym {
        st_name,
        st_info: 0x12, // STB_GLOBAL << 4 | STT_FUNC
        st_other: 0,
        st_shndx: 1,
        st_value,
        st_size: 0,
    }
}

const ALPHA_VALUE: u64 = 0x1000;
const BETA_VALUE: u64 = 0x2000;

/// A symbol table with one undefined entry, then alpha and beta.
fn symbols(dynstr: &mut Vec<u8>) -> Vec<Elf64Sym> {
    let alpha = push(dynstr, b"alpha");
    let beta = push(dynstr, b"beta");

    vec![
        Elf64Sym {
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
        },
        function(alpha, ALPHA_VALUE),
        function(beta, BETA_VALUE),
    ]
}

fn cstr(name: &'static CStr) -> *const core::ffi::c_char {
    name.as_ptr()
}

#[test]
fn hashes_match_the_reference_implementation() {
    // Values from the C these replace, so a port that is off by a bit is
    // caught here rather than by a symbol that silently does not resolve.
    let cases: &[(&CStr, u32, u32)] = &[
        (c"", 0x0000_0000, 0x0000_1505),
        (c"a", 0x0000_0061, 0x0002_b606),
        (c"main", 0x0007_37fe, 0x7c9a_7f6a),
        (c"alpha", 0x0068_36e1, 0x0f17_6c2b),
        (c"beta", 0x0006_8ca1, 0x7c94_89a1),
        (c"__cxa_finalize", 0x0bea_6495, 0x6dce_65d0),
    ];

    for (name, elf, gnu) in cases {
        assert_eq!(vexcore_elf_hash(cstr(name)), *elf, "elf hash of {:?}", name);
        assert_eq!(vexcore_gnu_hash(cstr(name)), *gnu, "gnu hash of {:?}", name);
    }
}

#[test]
fn gnu_lookup_answers_the_address_of_a_hashed_symbol() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let shift2 = 5u32;

    // The filter and the table the linker would have built for one symbol
    // starting at index 1, as the last entry of its chain.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> shift2) % 64)),];
    let bucket = [1u32];
    let chain = [alpha_hash | 1];

    let mut sym_type = 0u8;

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            shift2,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            &mut sym_type,
        )
    };

    assert_eq!(found, ALPHA_VALUE);
    assert_eq!(sym_type, 0x2, "STT_FUNC");
}

#[test]
fn gnu_lookup_refuses_a_name_the_filter_excludes() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let beta_hash = vexcore_gnu_hash(cstr(c"beta"));

    // The filter only has room for alpha's bits, which is the whole point of
    // it: beta is answered without touching the bucket or the chain.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    let bucket = [1u32];
    let chain = [alpha_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            beta_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0);
}

#[test]
fn gnu_lookup_refuses_a_name_the_chain_does_not_hold() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));

    // The filter and the bucket are alpha's, the name asked for is not: the
    // hash half of the comparison passes and the name half is what has to
    // reject it, which is the case a bucket collision takes.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    let bucket = [1u32];
    let chain = [alpha_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0);
}

#[test]
fn gnu_lookup_refuses_a_bucket_index_past_the_symbols() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    // One past the end of the table, which a malformed image can name.
    let bucket = [syms.len() as u32];
    let chain = [alpha_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0, "an out-of-range bucket index was followed");
}

#[test]
fn elf_lookup_answers_the_address_of_a_chained_symbol() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_elf_hash(cstr(c"alpha"));
    let bucket = [1u32];
    // Index 1 is alpha, and its chain entry ends the walk.
    let chain = [0u32, 0];

    let mut sym_type = 0u8;

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            &mut sym_type,
        )
    };

    assert_eq!(found, ALPHA_VALUE);
    assert_eq!(sym_type, 0x2, "STT_FUNC");
}

#[test]
fn elf_lookup_walks_the_chain_and_then_gives_up() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    // The bucket names alpha, whose chain entry names beta: the miss is on the
    // first link and the hit on the second. An index of zero would end the walk
    // before it started - that is what STN_UNDEF means - so the chain has to
    // start at a real symbol for this to test anything.
    let bucket = [1u32];
    let chain = [0u32, 2, 0];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            vexcore_elf_hash(cstr(c"beta")),
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, BETA_VALUE, "the second link of the chain was not reached");

    // And a name the chain does not hold runs out of links.
    let missing = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"gamma"),
            vexcore_elf_hash(cstr(c"gamma")),
            core::ptr::null_mut(),
        )
    };

    assert_eq!(missing, 0);
}

#[test]
fn a_name_offset_past_its_string_table_is_a_miss() {
    let mut dynstr = Vec::new();
    let mut syms = symbols(&mut dynstr);

    // Past the end of the string table, which is what a corrupt image has.
    syms[1].st_name = dynstr.len() as u32;

    let alpha_hash = vexcore_elf_hash(cstr(c"alpha"));
    let bucket = [1u32];
    let chain = [0u32, 0];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0, "an offset past the string table was read");

    // The same offset through the GNU path: the bloom filter has to be built
    // to let this one through, so the miss is the string table's doing.
    let bloom = [(1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> 5) % 64)),];
    let gnu_bucket = [1u32];
    let gnu_chain = [alpha_hash | 1];

    let gnu_found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            5,
            bloom.as_ptr(),
            gnu_bucket.as_ptr(),
            gnu_chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(gnu_found, 0, "an offset past the string table was read");
}

#[test]
fn a_symbol_that_is_not_defined_here_is_never_the_answer() {
    let mut dynstr = Vec::new();
    let mut syms = symbols(&mut dynstr);

    // The name matches, the definition is elsewhere.
    syms[1].st_shndx = 0;

    let alpha_hash = vexcore_elf_hash(cstr(c"alpha"));
    let bucket = [1u32];
    let chain = [0u32, 0];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"alpha"),
            alpha_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0);
}

#[test]
fn empty_tables_are_refused_without_being_read() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let null_sym: *const Elf64Sym = core::ptr::null();
    let null_u8: *const u8 = core::ptr::null();
    let null_u32: *const u32 = core::ptr::null();

    let by_gnu = unsafe {
        vexcore_gnu_lookup(
            null_sym, 0, null_u8, 0, 0, 0, 0, 0, core::ptr::null(), null_u32, null_u32,
            cstr(c"alpha"), 0, core::ptr::null_mut(),
        )
    };
    assert_eq!(by_gnu, 0);

    let by_elf = unsafe {
        vexcore_elf_lookup(
            null_sym, 0, null_u8, 0, 0, null_u32, null_u32,
            cstr(c"alpha"), 0, core::ptr::null_mut(),
        )
    };
    assert_eq!(by_elf, 0);

    // The hash of a name that is not there still has to be computable: the
    // caller hashes before it looks.
    let _ = vexcore_gnu_hash(cstr(c"gamma"));
    let _ = syms.len();
}

/// The GOT walk over a synthetic image, `crate::got::scan`.
///
/// The image is built byte for byte - one `PT_LOAD` mapping the whole file at
/// `LOAD_VADDR`, one `PT_DYNAMIC`, then the tables the dynamic entry points
/// at - because what these tests pin is exactly the arithmetic between the
/// tables: a stride, a terminator, an extent. The byte-for-byte builder keeps
/// every offset visible in the test instead of hidden behind a struct the
/// real parser also uses.
mod got_walk {
    use crate::got::{scan, MemImage};

    const EH_SIZE: usize = 64;
    const PH_SIZE: usize = 56;
    const LOAD_VADDR: u64 = 0x1000;

    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;

    const DT_PLTRELSZ: i64 = 2;
    const DT_STRTAB: i64 = 5;
    const DT_SYMTAB: i64 = 6;
    const DT_RELA: i64 = 7;
    const DT_REL: i64 = 17;
    const DT_PLTREL: i64 = 20;
    const DT_JMPREL: i64 = 23;
    const DT_NULL: i64 = 0;

    const R_AARCH64_JUMP_SLOT: u32 = 1026;

    const SYM_SIZE: usize = 24;
    const RELA_SIZE: usize = 24;
    const REL_SIZE: usize = 16;
    const DYN_SIZE: usize = 16;

    fn put_u16(bytes: &mut Vec<u8>, at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut Vec<u8>, at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut Vec<u8>, at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// One `(r_offset, symbol index, type)` relocation, written as the shape
    /// `rela` says - the addend a Rela carries is the third word, and the
    /// stride the walk takes over the table is what these tests are about.
    fn put_reloc(bytes: &mut Vec<u8>, at: usize, rela: bool, r_offset: u64, sym: u64, r_type: u32) {
        put_u64(bytes, at, r_offset);
        put_u64(bytes, at + 8, (sym << 32) | r_type as u64);

        if rela {
            put_u64(bytes, at + 16, 0);
        }
    }

    /// One `(st_name offset, defined)` symbol entry.
    fn put_sym(bytes: &mut Vec<u8>, at: usize, st_name: u32, defined: bool) {
        put_u32(bytes, at, st_name);
        bytes[at + 4] = 0x12; // STB_GLOBAL << 4 | STT_FUNC
        bytes[at + 5] = 0;
        put_u16(bytes, at + 6, if defined { 1 } else { 0 });
        put_u64(bytes, at + 8, 0x4000);
        put_u64(bytes, at + 16, 0);
    }

    struct Image {
        bytes: Vec<u8>,
        data_at: usize,
        rela: bool,
        dyn_entries: Vec<(i64, u64)>,
        relocs: Vec<(u64, u64, u32)>,
        syms: Vec<(u32, bool)>,
        strings: Vec<u8>,
    }

    impl Image {
        fn new(rela: bool) -> Image {
            Image {
                bytes: Vec::new(),
                data_at: EH_SIZE + 2 * PH_SIZE,
                rela,
                dyn_entries: Vec::new(),
                relocs: Vec::new(),
                syms: vec![(0, false)],
                strings: vec![0],
            }
        }

        /// Appends `name` NUL-terminated and answers its offset.
        fn push(&mut self, name: &[u8]) -> u32 {
            let offset = self.strings.len() as u32;
            self.strings.extend_from_slice(name);
            self.strings.push(0);

            offset
        }

        fn build(mut self) -> MemImage {
            // The tables land after the headers, in the order a linker lays
            // them out; the addresses the dynamic entries carry are the file
            // offsets shifted by the one load segment's vaddr.
            let mut at = self.data_at;

            let dyn_at = at;
            at += DYN_SIZE * (self.dyn_entries.len() + 1);

            let reloc_size = if self.rela { RELA_SIZE } else { REL_SIZE };
            let relocs_at = at;
            at += reloc_size * self.relocs.len().max(1);

            let syms_at = at;
            at += SYM_SIZE * self.syms.len();

            let strings_at = at;

            self.bytes = vec![0u8; at + self.strings.len()];

            // The ELF header: little-endian 64-bit, two program headers.
            self.bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
            self.bytes[4] = 2; // ELFCLASS64
            self.bytes[5] = 1; // ELFDATA2LSB
            self.bytes[6] = 0; // ELFOSABI_NONE
            put_u16(&mut self.bytes, 16, 3); // e_type = ET_DYN
            put_u16(&mut self.bytes, 18, 0xb7); // e_machine = aarch64
            put_u32(&mut self.bytes, 20, 1); // e_version
            put_u64(&mut self.bytes, 24, 0); // e_entry
            put_u64(&mut self.bytes, 32, EH_SIZE as u64); // e_phoff
            put_u16(&mut self.bytes, 54, PH_SIZE as u16); // e_phentsize
            put_u16(&mut self.bytes, 56, 2); // e_phnum

            // The program headers: the load maps the whole file, the dynamic
            // entry names its own table.
            let file_len = self.bytes.len() as u64;

            put_u32(&mut self.bytes, EH_SIZE, PT_LOAD);
            put_u64(&mut self.bytes, EH_SIZE + 8, 0);
            put_u64(&mut self.bytes, EH_SIZE + 16, LOAD_VADDR);
            put_u64(&mut self.bytes, EH_SIZE + 32, file_len); // p_filesz
            put_u64(&mut self.bytes, EH_SIZE + 40, file_len); // p_memsz

            put_u32(&mut self.bytes, EH_SIZE + PH_SIZE, PT_DYNAMIC);
            let dyn_vaddr = LOAD_VADDR + dyn_at as u64;
            put_u64(&mut self.bytes, EH_SIZE + PH_SIZE + 8, dyn_at as u64);
            put_u64(&mut self.bytes, EH_SIZE + PH_SIZE + 16, dyn_vaddr);
            put_u64(
                &mut self.bytes,
                EH_SIZE + PH_SIZE + 32,
                (DYN_SIZE * (self.dyn_entries.len() + 1)) as u64,
            );

            // The dynamic entries, the relocations, the symbols, the strings.
            for (index, (tag, value)) in self.dyn_entries.iter().enumerate() {
                put_u64(&mut self.bytes, dyn_at + index * DYN_SIZE, *tag as u64);
                put_u64(&mut self.bytes, dyn_at + index * DYN_SIZE + 8, *value);
            }
            put_u64(&mut self.bytes, dyn_at + self.dyn_entries.len() * DYN_SIZE, DT_NULL as u64);
            put_u64(&mut self.bytes, dyn_at + self.dyn_entries.len() * DYN_SIZE + 8, 0);

            for (index, (r_offset, sym, r_type)) in self.relocs.iter().enumerate() {
                put_reloc(
                    &mut self.bytes,
                    relocs_at + index * reloc_size,
                    self.rela,
                    *r_offset,
                    *sym,
                    *r_type,
                );
            }

            for (index, (st_name, defined)) in self.syms.iter().enumerate() {
                put_sym(&mut self.bytes, syms_at + index * SYM_SIZE, *st_name, *defined);
            }

            self.bytes[strings_at..].copy_from_slice(&self.strings);

            MemImage(self.bytes)
        }
    }

    /// The relocation table shape under test, `rela` or `rel`.
    fn image_with_target_at(rela: bool, target_index: usize, trailing: bool) -> (MemImage, u64) {
        let mut image = Image::new(rela);

        let alpha = image.push(b"alpha");
        let beta = image.push(b"beta");

        // The symbol table: the null entry, alpha, beta. The relocation at
        // `target_index` names beta; the walk has to step over alpha's entry
        // first, which is the stride these tests exist for.
        image.syms.extend_from_slice(&[(alpha, true), (beta, true)]);

        let got_off = 0xdead_0000u64 + target_index as u64;
        image.relocs.push((0xcafe_0000, 1, R_AARCH64_JUMP_SLOT)); // alpha
        image.relocs.push((got_off, 2, R_AARCH64_JUMP_SLOT)); // beta, the target
        if trailing {
            // A third entry after the target, so a walk that overshoots by a
            // stride still has bytes to land in and misread.
            image.relocs.push((0xbeef_0000, 1, R_AARCH64_JUMP_SLOT));
        }

        // Layout-dependent values are filled in by `build`'s order: the sizes
        // are known here, the offsets are not - so the entries are appended
        // after the tables' positions are computable. `build` above writes
        // the tables in a fixed order; this mirrors it to compute offsets.
        // The dynamic table holds the five entries below plus `DT_NULL`.
        let reloc_size = if rela { RELA_SIZE } else { REL_SIZE };
        let dyn_len = 6;
        let dyn_at = EH_SIZE + 2 * PH_SIZE;
        let relocs_at = dyn_at + DYN_SIZE * dyn_len;
        let syms_at = relocs_at + reloc_size * image.relocs.len();
        let strings_at = syms_at + SYM_SIZE * image.syms.len();

        image.dyn_entries = vec![
            (DT_JMPREL, LOAD_VADDR + relocs_at as u64),
            (DT_PLTRELSZ, (reloc_size * image.relocs.len()) as u64),
            (DT_PLTREL, (if rela { DT_RELA } else { DT_REL }) as u64),
            (DT_SYMTAB, LOAD_VADDR + syms_at as u64),
            (DT_STRTAB, LOAD_VADDR + strings_at as u64),
        ];

        (image.build(), got_off)
    }

    fn found(image: &MemImage, wanted: &[u8]) -> Option<(u64, u64)> {
        let mut bias = 0u64;
        let mut got_off = 0u64;

        if scan(image, wanted, &mut bias, &mut got_off) {
            Some((bias, got_off))
        } else {
            None
        }
    }

    #[test]
    fn a_rela_table_strides_twenty_four_bytes() {
        // INFO: `DT_RELA` is what arm64 Android links use, and this used to
        //       be walked by 16: the target relocation sits at byte 24 of the
        //       table, which under the old stride was read as an entry header
        //       made of entry 0's addend - and roughly two thirds of all
        //       imported symbols went unfound.
        let (image, got_off) = image_with_target_at(true, 1, true);

        assert_eq!(
            found(&image, b"beta"),
            Some((LOAD_VADDR, got_off)),
            "the second entry of a RELA table was not found"
        );
    }

    #[test]
    fn a_rel_table_strides_sixteen_bytes() {
        let (image, got_off) = image_with_target_at(false, 1, true);

        assert_eq!(
            found(&image, b"beta"),
            Some((LOAD_VADDR, got_off)),
            "the second entry of a REL table was not found"
        );
    }

    #[test]
    fn a_name_the_table_does_not_import_is_a_miss() {
        let (image, _) = image_with_target_at(true, 1, true);

        assert_eq!(found(&image, b"gamma"), None);
    }

    #[test]
    fn the_dynamic_walk_stops_at_its_first_null() {
        // INFO: Entries past `DT_NULL` are padding. This one carries a zeroed
        //       `DT_JMPREL`, which a walk that read it would let overwrite
        //       the real one and answer "no table" for an image that has one.
        let (mut image, got_off) = image_with_target_at(true, 1, false);
        let len = image.0.len();

        // The trailing tag sits after the terminator `build` wrote: five real
        // entries, the null, then the poison.
        let dyn_at = EH_SIZE + 2 * PH_SIZE;
        let poison_at = dyn_at + DYN_SIZE * 6;
        assert!(poison_at + DYN_SIZE <= len, "image shorter than the poison");
        put_u64(&mut image.0, poison_at, DT_JMPREL as u64);
        put_u64(&mut image.0, poison_at + 8, 0);
        // The dynamic segment has to cover the poison for the walk to see it.
        put_u64(&mut image.0, EH_SIZE + PH_SIZE + 32, (DYN_SIZE * 7) as u64);

        assert_eq!(
            found(&image, b"beta"),
            Some((LOAD_VADDR, got_off)),
            "a padded entry past DT_NULL overwrote a live one"
        );
    }

    #[test]
    fn headers_this_target_cannot_read_are_refused() {
        let (mut image, _) = image_with_target_at(true, 1, false);

        // A big-endian image is a refusal, not a misparse.
        image.0[5] = 2;
        assert_eq!(found(&image, b"beta"), None, "a big-endian image was walked");

        // Back to little-endian; a zero entry size makes every program
        // header the same bytes.
        let (mut image, _) = image_with_target_at(true, 1, false);
        put_u16(&mut image.0, 54, 0);
        assert_eq!(found(&image, b"beta"), None, "a zero e_phentsize was walked");

        // A relocation table past the end of the file is a refusal.
        let (mut image, _) = image_with_target_at(true, 1, false);
        let dyn_at = EH_SIZE + 2 * PH_SIZE;
        put_u64(&mut image.0, dyn_at + 8, LOAD_VADDR + 0xf000_0000); // DT_JMPREL's value
        assert_eq!(found(&image, b"beta"), None);
    }
}

#[test]
fn a_cyclic_sysv_chain_is_a_miss_rather_than_a_hang() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    // chain[1] names itself: a corrupt image can carry that, and a walk
    // without a progress bound would follow it forever. The cap is one entry
    // per symbol, so this answers a miss.
    let bucket = [1u32];
    let chain = [0u32, 1];

    let found = unsafe {
        vexcore_elf_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"gamma"),
            vexcore_elf_hash(cstr(c"gamma")),
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, 0, "a self-naming chain entry was followed forever");
}

#[test]
fn gnu_lookup_continues_past_the_first_entry_of_a_chain() {
    let mut dynstr = Vec::new();
    let syms = symbols(&mut dynstr);

    let alpha_hash = vexcore_gnu_hash(cstr(c"alpha"));
    let beta_hash = vexcore_gnu_hash(cstr(c"beta"));
    let shift2 = 5u32;

    // The bucket names alpha, whose chain entry is *not* the last; beta's is.
    // The answer therefore depends on the index moving forward by one - the
    // continuation every other test leaves unexercised.
    let bloom = [
        (1usize << (alpha_hash % 64)) | (1usize << ((alpha_hash >> shift2) % 64))
            | (1usize << (beta_hash % 64))
            | (1usize << ((beta_hash >> shift2) % 64)),
    ];
    let bucket = [1u32];
    let chain = [alpha_hash & !1, beta_hash | 1];

    let found = unsafe {
        vexcore_gnu_lookup(
            syms.as_ptr(),
            syms.len(),
            dynstr.as_ptr(),
            dynstr.len(),
            1,
            1,
            1,
            shift2,
            bloom.as_ptr(),
            bucket.as_ptr(),
            chain.as_ptr(),
            cstr(c"beta"),
            beta_hash,
            core::ptr::null_mut(),
        )
    };

    assert_eq!(found, BETA_VALUE, "the second entry of the chain was not reached");
}
