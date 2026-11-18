#ifndef VEXCORE_H
#define VEXCORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The Rust half of the loader, as C sees it
   (rust/vexcore/src/{hash,lookup,got}.rs).

   Only values cross this line, never state: a name in, an address out, plus the
   tables the answer is searched in. Nothing on the far side allocates, owns a
   descriptor or keeps anything between calls. The ElfImg those tables belong to
   stays a C structure; Rust is told which tables to read and how long they are,
   so a change to that structure cannot silently change a call's meaning. */

/* One entry of a 64-bit ELF symbol table, laid out as the image's own .dynsym
   is: the field order and widths are the file format's, not a choice here. */
struct vexcore_symbol {
  uint32_t st_name;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};

/* Checked, not assumed: this is reinterpreted over file bytes, and padding that
   disagreed with the other side would read the wrong fields rather than fail to
   build. Both spellings, because the loader is C18 and the daemon C99. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct vexcore_symbol) == 24, "vexcore_symbol must match the Rust Elf64Sym");
#else
typedef char vexcore_symbol_must_match_the_rust_elf64sym[(sizeof(struct vexcore_symbol) == 24) ? 1 : -1];
#endif

uint32_t vexcore_elf_hash(const char *name);

uint32_t vexcore_gnu_hash(const char *name);

/* The two hash-table lookups: the symbol's st_value, or 0 when the name is not
   in the table, with the symbol's type written to `sym_type` on a hit.

   `dynstr_size` bounds `st_name`: a symbol pointing past the string table is a
   miss, not a read off the end of the mapping. The chain arrays have no recorded
   length and are walked by the index the previous entry supplied, bounded by
   `dynsym_count`. */
uintptr_t vexcore_gnu_lookup(const struct vexcore_symbol *dynsym, size_t dynsym_count,
                             const char *dynstr, size_t dynstr_size,
                             uint32_t gnu_nbucket, uint32_t gnu_symndx,
                             uint32_t gnu_bloom_size, uint32_t gnu_shift2,
                             const uintptr_t *bloom, const uint32_t *bucket,
                             const uint32_t *chain,
                             const char *name, uint32_t hash, unsigned char *sym_type);

uintptr_t vexcore_elf_lookup(const struct vexcore_symbol *dynsym, size_t dynsym_count,
                             const char *dynstr, size_t dynstr_size,
                             uint32_t nbucket, const uint32_t *bucket,
                             const uint32_t *chain,
                             const char *name, uint32_t hash, unsigned char *sym_type);

/* The address a symbol's PLT entry jumps through, as (bias, got_offset): `bias`
   is the image's lowest load address, `got_offset` the relocation's r_offset.
   False when the file has no such slot, which is also how an unreadable file
   answers. */
bool vexcore_got_offset(const char *path, const char *symbol,
                        uint64_t *out_bias, uint64_t *out_got_off);

#endif /* VEXCORE_H */
