#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <unistd.h>

#define LOG_TAG "zygisk-elfutil"

#include "logging.h"

#include "elf_util.h"

#include "vexcore.h"

/* INFO: The load base is resolved from the process maps, so the maps reader and
         its entry shape are needed here. misc.h is not included by elf_util.h:
         the host tests compile this file on its own. */
#include "misc.h"

#include "xz.h"

/* INFO: xz-embedded in XZ_INTERNAL_CRC32 mode calls these from the stream
         decoder; the kernel normally supplies them. Software CRC32, same
         table as the reference build. */
void xz_crc32_init(void) {}

uint32_t xz_crc32(const uint8_t *buf, size_t size, uint32_t crc) {
  crc = ~crc;

  for (size_t i = 0; i < size; i++) {
    crc ^= buf[i];

    for (int bit = 0; bit < 8; bit++) {
      uint32_t mask = 0U - (crc & 1U);

      crc = (crc >> 1U) ^ (0xedb88320U & mask);
    }
  }

  return ~crc;
}

/* INFO: Mini-debug info (.gnu_debugdata) support. The section holds an XZ
          stream (LZMA2 inside the XZ container) that decompresses into a
          small ELF carrying the full .symtab of an otherwise stripped
          library. LZMA1 "alone" streams are not decodable here: the container
          differs and the toolchains that emit mini-debug info produce XZ. */

/* INFO: The stream carries no uncompressed size a reader can trust ahead of
          decoding, so the output grows on demand. 64 MiB is the same cap the
          alone-stream decoder used and far above any real payload. */
#define XZ_DICT_LIMIT (1u << 26)
#define XZ_OUT_LIMIT (64u << 20)

static bool xz_decompress(const uint8_t *in, size_t in_size, uint8_t **out_buf, size_t *out_size) {
  struct xz_dec *decoder = xz_dec_init(XZ_DYNALLOC, XZ_DICT_LIMIT);
  if (decoder == NULL) return false;

  size_t capacity = 64u << 10;
  uint8_t *out = (uint8_t *)malloc(capacity);
  if (out == NULL) {
    xz_dec_end(decoder);

    return false;
  }

  struct xz_buf buffer = {
    .in = in,
    .in_pos = 0,
    .in_size = in_size,
    .out = out,
    .out_pos = 0,
    .out_size = capacity
  };

  bool ok = false;

  for (;;) {
    enum xz_ret result = xz_dec_run(decoder, &buffer);

    if (result == XZ_STREAM_END) {
      ok = true;

      break;
    }

    /* INFO: XZ_DEC_ANY_CHECK accepts every integrity check, so this should
             not surface; the stream is undecodable either way, and looping
             without consuming input would only spin. */
    if (result == XZ_UNSUPPORTED_CHECK) break;
    if (result != XZ_OK) break;

    if (buffer.out_pos == buffer.out_size) {
      /* INFO: The output filled up mid-stream: double it and carry on. */
      if (capacity >= XZ_OUT_LIMIT) break;

      size_t bigger = capacity * 2;
      uint8_t *grown = (uint8_t *)realloc(out, bigger);
      if (grown == NULL) break;

      out = grown;
      capacity = bigger;
      buffer.out = out;
      buffer.out_size = capacity;

      continue;
    }

    /* INFO: XZ_OK with output still to spare means the input ran out before
             the stream ended. */
    if (buffer.in_pos == buffer.in_size) break;
  }

  xz_dec_end(decoder);

  if (!ok) {
    free(out);

    return false;
  }

  /* INFO: The growth doubling leaves a 64 MiB allocation for what is
           usually a few hundred KiB of symbols; give the excess back. */
  /* INFO: A zero-length stream is a valid XZ stream, so out_pos can be zero
           here. realloc(out, 0) is free(out) on bionic and returns NULL, which
           the "keep the larger block" rule below would mistake for a refusal
           and hand back a dangling pointer - the caller then frees it again.
           A zero result keeps the allocation and reports a zero size; the
           caller's ELF-header check rejects it and frees exactly once. */
  if (buffer.out_pos > 0 && buffer.out_pos < capacity) {
    uint8_t *shrunk = (uint8_t *)realloc(out, buffer.out_pos);

    /* INFO: realloc to a smaller size does not move on any allocator this
             runs over; a refusal keeps the larger block, which is only
             memory held a little longer, never a wrong answer. */
    if (shrunk != NULL) out = shrunk;
  }

  *out_buf = out;
  *out_size = buffer.out_pos;

  return true;
}

/* INFO: A string table is only safe to `strcmp` through when its last byte
         is the NUL every name inside it relies on: the tables come out of a
         file this code did not produce, and one that ends mid-name would
         have every read after it walk past the mapping. An empty table is
         not one either. */
static bool strtable_terminated(const char *table, size_t size) {
  return table != NULL && size > 0 && table[size - 1] == '\0';
}

static bool parse_gnu_debugdata(ElfImg *img, const uint8_t *data, size_t size) {
  /* INFO: The GNU toolchain emits the raw XZ stream while Android prefixes a
            4-byte CRC32, so both positions are tried. */
  static const size_t kOffsets[] = { 4, 0 };

  for (size_t i = 0; i < sizeof(kOffsets) / sizeof(kOffsets[0]); i++) {
    size_t off = kOffsets[i];
    if (size <= off + 8) continue;

    uint8_t *out = NULL;
    size_t out_size = 0;
    if (!xz_decompress(data + off, size - off, &out, &out_size)) continue;
    if (out_size < sizeof(ElfW(Ehdr)) || memcmp(out, ELFMAG, SELFMAG) != 0) {
      free(out);

      continue;
    }

    ElfW(Ehdr) *deh = (ElfW(Ehdr) *)out;
    /* INFO: The extent checks are written as subtraction because the fields
              are file values: an addition can wrap past `out_size` and pass,
              and a wrapped section table pointer is then dereferenced. The
              entry size has to be the structure's own for the same reason
              the outer walks require it. */
    if (deh->e_shoff == 0 || deh->e_shnum == 0 ||
        deh->e_shentsize != sizeof(ElfW(Shdr)) ||
        deh->e_shoff > out_size ||
        deh->e_shnum > (out_size - deh->e_shoff) / sizeof(ElfW(Shdr))) {
      free(out);

      continue;
    }

    ElfW(Shdr) *dshdrs = (ElfW(Shdr) *)(out + deh->e_shoff);

    for (unsigned int j = 0; j < deh->e_shnum; j++) {
      ElfW(Shdr) *sh = &dshdrs[j];
      if (sh->sh_type != SHT_SYMTAB || sh->sh_link >= deh->e_shnum) continue;

      ElfW(Shdr) *str_sh = &dshdrs[sh->sh_link];
      if (sh->sh_offset > out_size || sh->sh_size > out_size - sh->sh_offset) continue;
      if (str_sh->sh_offset > out_size || str_sh->sh_size > out_size - str_sh->sh_offset) continue;
      /* INFO: A stride other than the symbol structure's own would count
                more entries than the table holds and walk past its end. */
      if (sh->sh_entsize != sizeof(ElfW(Sym))) continue;
      if (!strtable_terminated((const char *)(out + str_sh->sh_offset), str_sh->sh_size)) continue;

      img->dd_symtab_start = (ElfW(Sym) *)(out + sh->sh_offset);
      img->dd_symtab_count = sh->sh_size / sh->sh_entsize;
      img->dd_strtab = (const char *)(out + str_sh->sh_offset);
      img->dd_strtab_size = str_sh->sh_size;

      break;
    }

    if (img->dd_symtab_start && img->dd_symtab_count > 0) {
      img->debugdata = out;

      LOGD("Loaded %zu mini-debug symbols from .gnu_debugdata of %s", img->dd_symtab_count, img->elf);

      return true;
    }

    img->dd_symtab_start = NULL;
    img->dd_symtab_count = 0;
    img->dd_strtab = NULL;
    img->dd_strtab_size = 0;
    free(out);
  }

  return false;
}

/* INFO: Everything below is internal to the ELF reader; keeping the symbols
         static avoids exporting them from the injected library. */
/* INFO: The two hashes and the two hash-table lookups below live in
         rust/vexcore now - vexcore.h is the C side of that boundary.

         They moved for the reason the whole split exists: the lookups read
         tables whose offsets and lengths came out of the file, and every access
         used to be preceded by a hand-written comparison saying so, next to a
         string comparison that could walk past the end of a mapping this
         process does not own. Slices answer the first once and `Option` the
         second, and the functions that remain here are the ones that need to
         know what an ElfImg is.
*/

static ElfW(Shdr) *offsetOf_Shdr(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Shdr) *)(((uintptr_t)head) + off);
}

static char *offsetOf_char(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (char *)(((uintptr_t)head) + off);
}

static ElfW(Sym) *offsetOf_Sym(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Sym) *)(((uintptr_t)head) + off);
}

static ElfW(Word) *offsetOf_Word(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Word) *)(((uintptr_t)head) + off);
}

/* INFO: The load base is looked up in the maps, as the reference does, rather
          than through dl_iterate_phdr. The linker only lists an object once it
          has actually mapped it, so the maps answer for a live library, while
          the program header walk also walks whatever the resolver itself
          mapped - a plain file view that is not the loaded image and would be
          picked whenever it sorts below the real one.

          A bare soname is matched against the last path component, since the
          caller has no directory to compare against and every mapped path has
          one. */
static bool _find_module_base(ElfImg *img) {
  /* INFO: The reader that leaves no trace. This runs inside the injected
            process, which is exactly where a read of /proc/self/maps is
            something a detector can look for: the plain reader updates the
            file's access time, and the fork-based one hands the descriptor
            over from a child instead. It costs a fork per lookup, which is
            why the tracer and the daemon keep using the plain one - their
            reads are their own and nobody is watching them. */
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) {
    LOGE("Failed to read maps for %s", img->elf);

    return false;
  }

  bool want_basename = strchr(img->elf, '/') == NULL;

  /* INFO: The size of the whole file, used to recognise the plain file view
            this process may already hold of the same library: it spans the file
            and nothing else, where a loaded image has a header map first and
            segments after it. It is never zero - the caller has already
            rejected files that do not hold a header. */
  size_t whole_size = img->size;

  bool found = false;

  for (size_t i = 0; i < maps->length && !found; i++) {
    const struct map_entry *entry = &maps->maps[i];

    if (entry->path == NULL || entry->path[0] == '[') continue;

    const char *base = strrchr(entry->path, '/');
    base = base == NULL ? entry->path : base + 1;

    bool matched = want_basename ? strcmp(base, img->elf) == 0
                                 : strcmp(entry->path, img->elf) == 0;
    if (!matched) continue;

    /* INFO: Skipped for the reason above: a file-sized mapping of the same path
              is data, not the image the linker loaded. */
    uintptr_t span = entry->end - entry->start;
    if (span >= whole_size && span - whole_size < 4096) continue;

    /* INFO: Every file offset in a dynamic image is relative to the load bias,
              so this yields it from any segment - the header mapping does not
              have to be present, nor listed first. */
    if (entry->start < entry->offset) continue;

    img->base = (void *)(entry->start - entry->offset);
    found = true;
  }

  free_maps(maps);

  return found;
}

/* INFO: One predicate for every table the linear scan walks, so the counting
          pass below and the filling pass in _load_symtabs() cannot disagree on
          which symbols exist.

          SHN_UNDEF is excluded here as well as in the original file-symtab
          filter: such a symbol is a declaration the linker never resolved, so
          its st_value is 0 and turning it into an address would hand the caller
          a NULL it would then call. */
static bool zn_collectable_symbol(ElfW(Sym) *sym, size_t strtab_size) {
  if (sym->st_name == 0 || sym->st_name >= strtab_size) return false;
  if (sym->st_shndx == SHN_UNDEF) return false;

  unsigned int st_type = ELF_ST_TYPE(sym->st_info);

  return (st_type == STT_FUNC || st_type == STT_OBJECT) && sym->st_size > 0;
}

static size_t calculate_valid_symtabs_amount(ElfImg *img) {
  size_t count = 0;

  /* INFO: .dynsym is counted next to .symtab and the mini-debug table, which is
            what lets a prefix lookup or a forEach walk reach the exported
            symbols of a stripped library at all - those keep .dynsym after
            .symtab is gone. The flags are the same ones _load_symtabs fills by,
            so the two passes cannot disagree on which symbols exist. */
  bool has_file_symtab = img->symtab_start != NULL && img->symstr_offset_for_symtab != 0 && img->symtab_count > 0;
  bool has_dynsym = img->dynsym_start != NULL && img->dynsym_count > 0 && img->strtab_start != NULL && img->strtab != NULL;
  if (!has_file_symtab && !has_dynsym && img->dd_symtab_start == NULL) {
    LOGE("No .symtab, no .dynsym and no mini-debug symbols available, cannot count valid symbols");

    return 0;
  }

  ElfW(Shdr) *symtab_str_shdr = NULL;
  if (has_file_symtab && img->symtab && img->section_header && img->symtab->sh_link < img->header->e_shnum)
    symtab_str_shdr = img->section_header + img->symtab->sh_link;

  /* INFO: zn_collectable_symbol is the one predicate - it bounds the name
            offset against the string table's own size, so no separate check
            is written out here (and a broken table does not log a warning
            per symbol, which a large one could spin for minutes). */
  if (has_file_symtab) for (ElfW(Off) i = 0; i < img->symtab_count; i++) {
    if (zn_collectable_symbol(&img->symtab_start[i], symtab_str_shdr != NULL ? symtab_str_shdr->sh_size : SIZE_MAX))
      count++;
  }

  if (has_dynsym) for (size_t i = 0; i < img->dynsym_count; i++) {
    if (zn_collectable_symbol(&img->dynsym_start[i], img->strtab->sh_size))
      count++;
  }

  if (img->dd_symtab_start) for (size_t i = 0; i < img->dd_symtab_count; i++) {
    if (zn_collectable_symbol(&img->dd_symtab_start[i], img->dd_strtab_size))
      count++;
  }

  return count;
}

void ElfImg_destroy(ElfImg *img) {
  if (!img) return;

  if (img->symtabs_) {
    free(img->symtabs_);
    img->symtabs_ = NULL;
  }

  if (img->debugdata) {
    free(img->debugdata);
    img->debugdata = NULL;
  }

  if (img->elf) {
    free(img->elf);
    img->elf = NULL;
  }

  if (img->header) {
    munmap(img->header, img->size);
    img->header = NULL;
  }

  free(img);
}

/* INFO: Opens the image, maps it, and checks what it says it is before a byte
         is read through the mapping. The load base is resolved before the mmap
         and never after: that mapping adds a whole-file view of this same path
         to the maps, which sorts below the real loaded image often enough to be
         picked as the base - and every address derived from it would be
         garbage. */
static bool elf_map_file(ElfImg *img, const char *elf, bool base_provided) {
  int fd = open(elf, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    LOGE("failed to open %s", elf);

    ElfImg_destroy(img);

    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    LOGE("fstat() failed for %s", elf);

    close(fd);
    ElfImg_destroy(img);

    return false;
  }

  img->size = st.st_size;

  if (img->size <= sizeof(ElfW(Ehdr))) {
    LOGE("Invalid file size %zu for %s", img->size, elf);

    close(fd);
    ElfImg_destroy(img);

    return false;
  }

  /* INFO: Resolved before the mmap below, and never after it. That mapping adds
            a whole-file view of this very path to the maps, which sorts below
            the real loaded image often enough to be picked as the base - and
            every symbol address derived from it would be garbage, typically
            unmapped. The file size is already known here because the scan needs
            it to recognise such a view for what it is. */
  if (!base_provided && !_find_module_base(img)) {
    LOGE("Failed to find the load base of %s in the process maps", elf);

    close(fd);
    ElfImg_destroy(img);

    return false;
  }

  img->header = (ElfW(Ehdr) *)mmap(NULL, img->size, PROT_READ, MAP_PRIVATE, fd, 0);

  close(fd);

  if (img->header == MAP_FAILED) {
    LOGE("mmap() failed for %s", elf);

    img->header = NULL;
    ElfImg_destroy(img);

    return false;
  }

  if (memcmp(img->header->e_ident, ELFMAG, SELFMAG) != 0) {
    LOGE("Invalid ELF header for %s", elf);

    ElfImg_destroy(img);

    return false;
  }

  /* INFO: The class has to match the ElfW() types every later access is spelled
            with. A 32-bit object read through 64-bit structures would have its
            e_phoff/e_shoff/e_phnum taken from the wrong offsets, and the walks
            below would then chase whatever those bytes happened to say. */
  if (img->header->e_ident[EI_CLASS] != (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32)) {
    LOGE("Unsupported ELF class in %s", elf);

    ElfImg_destroy(img);

    return false;
  }

  /* INFO: The byte order has to be this target's own for the same reason: a
            big-endian image passes the magic and class checks and then hands
            back offsets that are every field's bytes reversed. */
  if (img->header->e_ident[EI_DATA] != ELFDATA2LSB) {
    LOGE("Unsupported ELF data encoding in %s", elf);

    ElfImg_destroy(img);

    return false;
  }

  return true;
}

/* INFO: The first PT_LOAD at offset 0 carries the header, and the difference
         between where it asks to be and where it sits is the bias. It has to be
         known before the base found in the maps means anything, which is why it
         is computed here rather than after the section walk. */
static void elf_compute_bias(ElfImg *img, const char *elf, bool base_provided) {
  /* INFO: The bias has to be known before the base found above can be
            normalized, so it is computed here rather than after the section
            walk. */
  bool bias_calculated = false;
  /* INFO: The table is walked by index, so it has to be proven to sit inside
            the mapped file first - otherwise e_phnum on its own decides how far
            past the end of the map phdr[i] reaches. The entry size is required
            to be the structure's own size for the same reason. */
  if (img->header->e_phoff > 0 && img->header->e_phnum > 0 &&
      img->header->e_phentsize == sizeof(ElfW(Phdr)) &&
      img->header->e_phoff <= img->size &&
      img->header->e_phnum <= (img->size - img->header->e_phoff) / sizeof(ElfW(Phdr))) {
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + img->header->e_phoff);

    for (int i = 0; i < img->header->e_phnum; ++i) {
      if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
        img->bias = phdr[i].p_vaddr - phdr[i].p_offset;
        bias_calculated = true;

        LOGD("Calculated bias %ld from PT_LOAD segment %d (vaddr %lx)", (long)img->bias, i, (unsigned long)phdr[i].p_vaddr);

        break;
      }
    }

    if (!bias_calculated) for (int i = 0; i < img->header->e_phnum; ++i) {
      if (phdr[i].p_type != PT_LOAD) continue;

      /* INFO: A segment that asks to sit below its own file offset would make
                the subtraction below wrap; such an image has no bias worth
                computing and the fallback keeps looking. */
      if (phdr[i].p_vaddr < phdr[i].p_offset) continue;

      img->bias = phdr[i].p_vaddr - phdr[i].p_offset;
      bias_calculated = true;

      LOGD("Calculated bias %ld from first PT_LOAD segment %d (vaddr %lx, offset %lx)",
          (long)img->bias, i, (unsigned long)phdr[i].p_vaddr, (unsigned long)phdr[i].p_offset);

      break;
    }
  }

  if (!bias_calculated)
    LOGE("Failed to calculate bias for %s. Assuming bias is 0.", elf);

  if (!base_provided && img->base != NULL) img->base = (void *)((uintptr_t)img->base + img->bias);
}

/* INFO: The SysV hash table. Parsed only when the section is large enough to
         hold the header and both of the arrays it points at; one that is not is
         left out rather than followed, and the lookup falls back to the linear
         walk. */
static void parse_sysv_hash_section(ElfImg *img, ElfW(Shdr) *section_h, const char *sname) {
  ElfW(Word) *d_un = offsetOf_Word(img->header, section_h->sh_offset);

  if (section_h->sh_size < 2 * sizeof(ElfW(Word))) {
    LOGW("SHT_HASH section %s too small", sname);

    return;
  }

  img->nbucket_ = d_un[0];

  /* INFO: Widen both counts before adding. `2 + nbucket + nchain` wraps in
           32 bits for a large nchain, which would pass a short section and
           leave chain_ pointing past the mapping; in 64 bits the sum cannot
           overflow and the section size is compared in full. */
  uint64_t needed = 2u + (uint64_t)img->nbucket_ + (uint64_t)d_un[1];
  bool counts_fit = (uint64_t)section_h->sh_size / sizeof(ElfW(Word)) >= needed;

  if (img->nbucket_ > 0 && counts_fit) {
    img->bucket_ = d_un + 2;
    img->chain_ = img->bucket_ + img->nbucket_;
    /* INFO: The header's own chain count, which the lookup's index bound has
              to fit: the walk is bounded by the symbol count, and a section
              holding fewer chain entries than that would be read past its
              end on the last links. */
    img->chain_len_ = d_un[1];

    return;
  }

  LOGW("Invalid SHT_HASH size or nbucket count in section %s", sname);

  img->nbucket_ = 0;
  img->chain_len_ = 0;
}

/* INFO: The GNU hash table. Same rule as above: the section has to hold the
         header, the bloom filter and the buckets before any of them is
         followed, and the chain that follows the buckets is checked against the
         section's own extent - it is the one table whose length is not in the
         header. */
static void parse_gnu_hash_section(ElfImg *img, ElfW(Shdr) *section_h, const char *sname) {
  ElfW(Word) *d_buf = offsetOf_Word(img->header, section_h->sh_offset);

  if (section_h->sh_size < 4 * sizeof(ElfW(Word))) {
    LOGW("SHT_GNU_HASH section %s too small", sname);

    return;
  }

  img->gnu_nbucket_ = d_buf[0];
  img->gnu_symndx_ = d_buf[1];
  img->gnu_bloom_size_ = d_buf[2];
  img->gnu_shift2_ = d_buf[3];

  size_t expected_min_size = 4 * sizeof(ElfW(Word)) +
                             img->gnu_bloom_size_ * sizeof(uintptr_t) +
                             img->gnu_nbucket_ * sizeof(uint32_t);

  if (img->gnu_nbucket_ == 0 || img->gnu_bloom_size_ == 0 || section_h->sh_size < expected_min_size) {
    LOGW("Invalid SHT_GNU_HASH size or parameters in section %s", sname);

    img->gnu_nbucket_ = 0;

    return;
  }

  img->gnu_bloom_filter_ = (uintptr_t *)(d_buf + 4);
  img->gnu_bucket_ = (uint32_t *)(img->gnu_bloom_filter_ + img->gnu_bloom_size_);
  img->gnu_chain_ = img->gnu_bucket_ + img->gnu_nbucket_;

  uintptr_t chain_start_offset = (uintptr_t)img->gnu_chain_ - (uintptr_t)img->header;
  if (chain_start_offset < section_h->sh_offset || chain_start_offset >= section_h->sh_offset + section_h->sh_size) {
    LOGW("Calculated GNU hash chain seems out of bounds for section %s", sname);

    img->gnu_nbucket_ = 0;
    img->gnu_chain_len_ = 0;

    return;
  }

  /* INFO: The chain's length is not written anywhere in the header; what the
            section can vouch for is the bytes that follow its start. The
            lookup walks chain[dynsym_count - gnu_symndx], so the count it
            walks by has to fit this. */
  size_t chain_bytes = (section_h->sh_offset + section_h->sh_size) - (size_t)chain_start_offset;
  img->gnu_chain_len_ = (uint32_t)(chain_bytes / sizeof(uint32_t));
}

/* INFO: Walks the section table once and records where each table it needs
         lives: the two symbol tables, the string table their names come from,
         the two hash tables, and the mini-debug payload if there is one. The
         two symbol table headers are handed back because their linked string
         tables are resolved in a second pass, after this loop has seen every
         section. */
static void elf_walk_sections(ElfImg *img, const char *elf,
                              ElfW(Shdr) **out_dynsym_shdr, ElfW(Shdr) **out_symtab_shdr) {
  *out_dynsym_shdr = NULL;
  *out_symtab_shdr = NULL;

  /* INFO: e_shentsize is required to be the structure's own size as well,
            because the table is walked by adding it to a section pointer - any
            other stride would read the entries at the wrong places. And the
            table has to be inside the mapped file, for the same reason the
            program header table does. */
  if (img->header->e_shoff == 0 || img->header->e_shnum == 0 ||
      img->header->e_shentsize != sizeof(ElfW(Shdr)) ||
      img->header->e_shoff > img->size ||
      img->header->e_shnum > (img->size - img->header->e_shoff) / sizeof(ElfW(Shdr))) {
    LOGW("Section header table missing or invalid in %s", elf);
  } else {
    img->section_header = offsetOf_Shdr(img->header, img->header->e_shoff);
  }

  /* INFO: Nothing is checked about the program header table here: the walk
            that uses it is elf_compute_bias, and that is where its bounds are
            validated. This function's tables are the sections'. */

  char *section_str = NULL;
  size_t section_str_size = 0;

  if (img->section_header && img->header->e_shstrndx != SHN_UNDEF) {
    if (img->header->e_shstrndx < img->header->e_shnum) {
      ElfW(Shdr) *shstrtab_hdr = img->section_header + img->header->e_shstrndx;

      /* INFO: Every section name is read relative to this pointer, so the
                string table has to be inside the map before it is used as one.
                Its size is kept alongside it: each name is an offset into this
                table, and an offset that leaves it would be read as a string
                from whatever follows. The last byte has to be the NUL every
                name relies on, or the whole table is left unbound. */
      if (shstrtab_hdr->sh_offset <= img->size &&
          shstrtab_hdr->sh_size <= img->size - shstrtab_hdr->sh_offset &&
          strtable_terminated((const char *)offsetOf_char(img->header, shstrtab_hdr->sh_offset), shstrtab_hdr->sh_size)) {
        section_str = offsetOf_char(img->header, shstrtab_hdr->sh_offset);
        section_str_size = shstrtab_hdr->sh_size;
      } else {
        LOGW("Section header string table lies outside the file or is unterminated in %s", elf);
      }
    } else {
      LOGW("Section header string table index (%u) out of bounds (%u)", img->header->e_shstrndx, img->header->e_shnum);
    }
  } else {
    LOGW("Section header string table index not set or no section headers");
  }

  if (img->section_header) {
    uintptr_t shoff = (uintptr_t)img->section_header;
    for (int i = 0; i < img->header->e_shnum; i++, shoff += img->header->e_shentsize) {
      ElfW(Shdr) *section_h = (ElfW(Shdr *))shoff;

      /* INFO: Everything below turns sh_offset into a pointer into the mapped
                file, so a section whose extent leaves the map is skipped rather
                than followed. SHT_NOBITS occupies no file space - its sh_size
                is a memory size - and is therefore exempt. */
      if (section_h->sh_type != SHT_NOBITS && section_h->sh_type != SHT_NULL &&
          (section_h->sh_offset > img->size ||
           section_h->sh_size > img->size - section_h->sh_offset)) {
        LOGW("Section %d lies outside the file in %s, skipping", i, elf);

        continue;
      }

      /* INFO: sh_name is an offset into the string table and comes out of the
                file, so it is checked against that table's size before it is
                turned into a pointer. A name pointing past the end would
                otherwise be read as a string and compared - a read past the
                mapped file, on a file this code did not produce. */
      const char *sname = "<?>";
      if (section_str != NULL && section_h->sh_name < section_str_size) {
        sname = section_str + section_h->sh_name;
      }

      switch (section_h->sh_type) {
        case SHT_DYNSYM: {
          *out_dynsym_shdr = section_h;
          img->dynsym_offset = section_h->sh_offset;
          img->dynsym_start = offsetOf_Sym(img->header, img->dynsym_offset);
          /* INFO: The stride has to be the symbol structure's own size: any
                    other value would count more entries than the table holds
                    and walk past the mapped section on the last ones. */
          if (section_h->sh_entsize == sizeof(ElfW(Sym))) {
            img->dynsym_count = section_h->sh_size / section_h->sh_entsize;
          } else {
            LOGW("Section %s has sh_entsize %zu (!= %zu), .dynsym is unusable", sname, (size_t)section_h->sh_entsize, sizeof(ElfW(Sym)));

            img->dynsym_count = 0;
          }

          break;
        }
        case SHT_SYMTAB: {
          if (strcmp(sname, ".symtab") == 0) {
            *out_symtab_shdr = section_h;
            img->symtab_offset = section_h->sh_offset;
            img->symtab_size = section_h->sh_size;

            /* INFO: Same rule as .dynsym, for the same reason. */
            if (section_h->sh_entsize == sizeof(ElfW(Sym))) {
              img->symtab_count = img->symtab_size / section_h->sh_entsize;
            } else {
              LOGW("Section %s has sh_entsize %zu (!= %zu)", sname, (size_t)section_h->sh_entsize, sizeof(ElfW(Sym)));

              img->symtab_count = 0;
            }

            img->symtab_start = offsetOf_Sym(img->header, img->symtab_offset);
          }

          break;
        }
        case SHT_STRTAB: break;
        case SHT_PROGBITS: {
          if (section_str && strcmp(sname, ".gnu_debugdata") == 0 &&
              section_h->sh_offset <= img->size &&
              section_h->sh_size <= img->size - section_h->sh_offset) {
            parse_gnu_debugdata(img, (const uint8_t *)offsetOf_char(img->header, section_h->sh_offset), section_h->sh_size);
          }

          break;
        }
        case SHT_HASH: {
          parse_sysv_hash_section(img, section_h, sname);

          break;
        }
        case SHT_GNU_HASH: {
          parse_gnu_hash_section(img, section_h, sname);

          break;
        }
      }
    }
  }
}

/* INFO: Each symbol table names its string table by section index, and that
          index is only valid once the whole section table has been seen - which
          is why this runs after the walk rather than inside it.

          The linked table is validated like any other the walk binds: the
          section walk skips a section whose extent leaves the file, but the
          header it leaves behind still names it, so the extent and the NUL
          termination are checked here too before the table is used as one. */
static bool linked_strtable_ok(ElfImg *img, ElfW(Shdr) *strtab_hdr) {
  if (strtab_hdr->sh_type != SHT_STRTAB) return false;
  if (strtab_hdr->sh_offset > img->size || strtab_hdr->sh_size > img->size - strtab_hdr->sh_offset) return false;

  return strtable_terminated((const char *)offsetOf_char(img->header, strtab_hdr->sh_offset), strtab_hdr->sh_size);
}

static void elf_link_string_tables(ElfImg *img, ElfW(Shdr) *dynsym_shdr, ElfW(Shdr) *symtab_shdr) {
  ElfW(Shdr) *shdr_base = img->section_header;

  if (dynsym_shdr && shdr_base) {
    img->dynsym = dynsym_shdr;

    if (dynsym_shdr->sh_link < img->header->e_shnum) {
      ElfW(Shdr) *linked_strtab = shdr_base + dynsym_shdr->sh_link;

      if (linked_strtable_ok(img, linked_strtab)) {
        img->strtab = linked_strtab;
        img->symstr_offset = linked_strtab->sh_offset;
        img->strtab_start = (void *)offsetOf_char(img->header, img->symstr_offset);
      } else {
        LOGW("Section %u linked by .dynsym is not a usable string table (type %u)", dynsym_shdr->sh_link, linked_strtab->sh_type);
      }
    } else {
      LOGE(".dynsym sh_link (%u) is out of bounds (%u)", dynsym_shdr->sh_link, img->header->e_shnum);
    }
  }

  if (symtab_shdr && shdr_base) {
    img->symtab = symtab_shdr;

    if (symtab_shdr->sh_link < img->header->e_shnum) {
      ElfW(Shdr) *linked_strtab = shdr_base + symtab_shdr->sh_link;

      if (linked_strtable_ok(img, linked_strtab)) {
        /* INFO: For linear lookup; the size rides along so a name offset can
                  be checked against the table it is read from. */
        img->symstr_offset_for_symtab = linked_strtab->sh_offset;
        img->symstr_size_for_symtab = linked_strtab->sh_size;
      } else {
        LOGW("Section %u linked by .symtab is not a usable string table (type %u)", symtab_shdr->sh_link, linked_strtab->sh_type);

        img->symstr_offset_for_symtab = 0;
        img->symstr_size_for_symtab = 0;
      }
    } else {
      LOGE(".symtab sh_link (%u) is out of bounds (%u)", symtab_shdr->sh_link, img->header->e_shnum);

      img->symstr_offset_for_symtab = 0;
      img->symstr_size_for_symtab = 0;
    }
  } else {
    img->symtab_start = NULL;
    img->symtab_count = 0;
    img->symstr_offset_for_symtab = 0;
    img->symstr_size_for_symtab = 0;
  }
}

ElfImg *ElfImg_create(const char *elf, void *base) {
  ElfImg *img = (ElfImg *)calloc(1, sizeof(ElfImg));
  if (!img) {
    LOGE("Failed to allocate memory for ElfImg");

    return NULL;
  }

  img->elf = strdup(elf);
  if (!img->elf) {
    LOGE("Failed to duplicate elf path string");

    free(img);

    return NULL;
  }

  /* INFO: Two callers hand in a base and they mean two things unless the
            convention is pinned down. img->base is always the runtime address
            the ELF header is mapped at; when no base is given, the maps yield
            the load bias, which is that address minus the bias computed further
            down — so the found value is normalized by the bias as soon as it is
            known. */
  bool base_provided = base != NULL;

  if (base_provided) {
    img->base = base;

    LOGD("Using provided base address 0x%p for %s", base, elf);
  }

  if (!elf_map_file(img, elf, base_provided)) return NULL;

  elf_compute_bias(img, elf, base_provided);

  ElfW(Shdr) *dynsym_shdr = NULL;
  ElfW(Shdr) *symtab_shdr = NULL;

  elf_walk_sections(img, elf, &dynsym_shdr, &symtab_shdr);
  elf_link_string_tables(img, dynsym_shdr, symtab_shdr);

  if (!img->dynsym_start || !img->strtab_start) {
    if (img->header->e_type == ET_DYN) LOGE("Failed to find .dynsym or its string table (.dynstr) in %s", elf);
    else LOGW("No .dynsym or .dynstr found in %s (might be expected for ET_EXEC)", elf);
  }

  if (!img->gnu_bucket_ && !img->bucket_)
    LOGW("No hash table (.gnu.hash or .hash) found in %s. Dynamic symbol lookup might be slow or fail.", elf);

  return img;
}

static bool _load_symtabs(ElfImg *img);

bool ElfImg_load_symbols(ElfImg *img) {
  return _load_symtabs(img);
}

const char *getSymbName(ElfImg *img, ElfW(Sym) *sym) {
  if (img == NULL || sym == NULL) return NULL;

  /* INFO: Symbols coming from the mini-debug table resolve against the
            decompressed buffer's own string table. */
  if (img->dd_symtab_start != NULL &&
      (uintptr_t)sym >= (uintptr_t)img->dd_symtab_start &&
      (uintptr_t)sym < (uintptr_t)img->dd_symtab_start + img->dd_symtab_count * sizeof(ElfW(Sym))) {
    if (sym->st_name >= img->dd_strtab_size) return NULL;

    return img->dd_strtab + sym->st_name;
  }

  /* INFO: A .dynsym entry names itself through .dynstr, which is a different
            string table from the one .symtab uses. Now that the linear scan
            carries both, the table has to be picked by where the symbol came
            from - reading a .dynsym name offset out of .symstr would resolve
            to whatever string happens to sit at that offset. */
  if (img->dynsym_start != NULL && img->dynsym_count > 0 &&
      (uintptr_t)sym >= (uintptr_t)img->dynsym_start &&
      (uintptr_t)sym < (uintptr_t)img->dynsym_start + img->dynsym_count * sizeof(ElfW(Sym))) {
    if (img->strtab_start == NULL || img->strtab == NULL) return NULL;
    if (sym->st_name >= img->strtab->sh_size) return NULL;

    return (const char *)img->strtab_start + sym->st_name;
  }

  if (img->symstr_offset_for_symtab == 0 || sym->st_name >= img->symstr_size_for_symtab) return NULL;

  return (const char *)(offsetOf_char(img->header, img->symstr_offset_for_symtab) + sym->st_name);
}

static bool _load_symtabs(ElfImg *img) {
  if (img->symtabs_) return true;

  bool has_file_symtab = img->symtab_start != NULL && img->symstr_offset_for_symtab != 0 && img->symtab_count > 0;
  bool has_dynsym = img->dynsym_start != NULL && img->dynsym_count > 0 && img->strtab_start != NULL && img->strtab != NULL;
  bool has_dd_symtab = img->dd_symtab_start != NULL && img->dd_symtab_count > 0;
  if (!has_file_symtab && !has_dynsym && !has_dd_symtab) return false;

  img->symtabs_count_ = calculate_valid_symtabs_amount(img);
  if (img->symtabs_count_ == 0) {
    LOGW("No valid symbols (FUNC/OBJECT with size > 0) found in .symtab, .dynsym or .gnu_debugdata for %s", img->elf);

    return false;
  }

  img->symtabs_ = calloc(img->symtabs_count_, sizeof(ElfW(Sym) *));
  if (!img->symtabs_) {
    LOGE("Failed to allocate memory for symtabs array");

    return false;
  }

  size_t current_valid_index = 0;

  if (has_file_symtab) {
    /* INFO: The symtab's own string table is not walked here; each symbol this
              loop keeps is a pointer, and the name is read when someone asks
              for it. Only the header is needed, to bound the check below. */
    ElfW(Shdr) *symtab_str_shdr = (img->symtab && img->section_header && img->symtab->sh_link < img->header->e_shnum)
                                  ? img->section_header + img->symtab->sh_link
                                  : NULL;

    for (ElfW(Off) pos = 0; pos < img->symtab_count; pos++) {
      /* INFO: The bound is checked before the store, the way both sibling
                loops below do it: a predicate that drifts from the counting
                pass then fills short instead of writing past the array. */
      if (current_valid_index >= img->symtabs_count_) break;

      ElfW(Sym) *current_sym = &img->symtab_start[pos];

      if (!zn_collectable_symbol(current_sym, symtab_str_shdr != NULL ? symtab_str_shdr->sh_size : SIZE_MAX)) continue;

      img->symtabs_[current_valid_index] = current_sym;

      current_valid_index++;
    }
  }

  /* INFO: The exported symbols of a stripped library live here and nowhere
            else. They are what symbolLookup serves a prefix request from and
            what forEachSymbols walks, so a resolver over a system library that
            has no .symtab would otherwise report nothing at all. */
  if (has_dynsym) for (size_t pos = 0; pos < img->dynsym_count; pos++) {
    if (current_valid_index >= img->symtabs_count_) break;

    ElfW(Sym) *current_sym = &img->dynsym_start[pos];

    if (!zn_collectable_symbol(current_sym, img->strtab->sh_size)) continue;

    img->symtabs_[current_valid_index] = current_sym;

    current_valid_index++;
  }

  if (has_dd_symtab) for (size_t pos = 0; pos < img->dd_symtab_count && current_valid_index < img->symtabs_count_; pos++) {
    ElfW(Sym) *current_sym = &img->dd_symtab_start[pos];

    if (!zn_collectable_symbol(current_sym, img->dd_strtab_size)) continue;

    img->symtabs_[current_valid_index] = current_sym;

    current_valid_index++;
  }

  if (current_valid_index == 0) {
    free(img->symtabs_);
    img->symtabs_ = NULL;
    img->symtabs_count_ = 0;

    return false;
  }

  img->symtabs_count_ = current_valid_index;

  return true;
}

/* INFO: The GNU hash lookup, forwarded to the Rust half (see vexcore.h).

         What stays here is the part that needs to know what an ElfImg is: which
         fields hold the tables and which of them have to be present before any
         of it is worth reading. The guard also gains the check on `strtab` that
         the loop this replaces was missing - it dereferenced that pointer for
         the string table's size without ever having checked it.

         The tables are handed over rather than the image, so a change to this
         structure cannot quietly change the meaning of a call: it has to be
         made here, where the arguments are named. */
ElfW(Addr) GnuLookup(ElfImg *restrict img, const char *name, uint32_t hash, unsigned char *sym_type) {
  if (img->gnu_nbucket_ == 0 || img->gnu_bloom_size_ == 0 || img->gnu_bloom_filter_ == NULL ||
      img->gnu_bucket_ == NULL || img->gnu_chain_ == NULL || img->dynsym_start == NULL ||
      img->strtab_start == NULL || img->strtab == NULL) {
    return 0;
  }

  /* INFO: The chain walk indexes chain[dynsym_count - gnu_symndx], and the
          chain's length is only what its section holds: a hashed range that
          does not fit it is a malformed table, answered as a miss so the
          linear fallback can take over. */
  if (img->gnu_symndx_ > img->dynsym_count ||
      img->dynsym_count - img->gnu_symndx_ > img->gnu_chain_len_) {
    return 0;
  }

  return (ElfW(Addr))vexcore_gnu_lookup(
    (const struct vexcore_symbol *)img->dynsym_start, img->dynsym_count,
    (const char *)img->strtab_start, img->strtab->sh_size,
    img->gnu_nbucket_, img->gnu_symndx_, img->gnu_bloom_size_, img->gnu_shift2_,
    img->gnu_bloom_filter_, img->gnu_bucket_, img->gnu_chain_,
    name, hash, sym_type);
}

/* INFO: The SysV hash lookup, forwarded the same way.

         The chain has no recorded length in either format, so both sides walk it
         with the symbol count as the bound and stop when the entry they are on
         ends the chain - the same rule, stated once on each side of the call
         rather than written out at each link. */
ElfW(Addr) ElfLookup(ElfImg *restrict img, const char *restrict name, uint32_t hash, unsigned char *sym_type) {
  if (img->nbucket_ == 0 || img->bucket_ == NULL || img->chain_ == NULL ||
      img->dynsym_start == NULL || img->strtab_start == NULL || img->strtab == NULL) {
    return 0;
  }

  /* INFO: The chain is indexed by symbol index, so the symbol count has to
          fit the chain length the section header vouches for - the same
          rule the GNU guard above states for its own chain. */
  if (img->dynsym_count > img->chain_len_) {
    return 0;
  }

  return (ElfW(Addr))vexcore_elf_lookup(
    (const struct vexcore_symbol *)img->dynsym_start, img->dynsym_count,
    (const char *)img->strtab_start, img->strtab->sh_size,
    img->nbucket_, img->bucket_, img->chain_,
    name, hash, sym_type);
}

ElfW(Addr) LinearLookup(ElfImg *img, const char *restrict name, unsigned char *sym_type) {
  if (!_load_symtabs(img)) return 0;

  for (size_t i = 0; i < img->symtabs_count_; i++) {
    ElfW(Sym) *sym = img->symtabs_[i];

    /* INFO: Every entry here already passed zn_collectable_symbol, which is
              the one place SHN_UNDEF and the name-offset bound are decided. */
    const char *sym_name = getSymbName(img, sym);
    if (sym_name == NULL || strcmp(name, sym_name) != 0) continue;

    unsigned int type = ELF_ST_TYPE(sym->st_info);
    if (sym_type) *sym_type = type;

    return sym->st_value;
  }

  return 0;
}

static ElfW(Addr) getSymbOffset(ElfImg *img, const char *name, unsigned char *sym_type) {
  ElfW(Addr) offset = GnuLookup(img, name, vexcore_gnu_hash(name), sym_type);
  if (offset != 0) return offset;

  offset = ElfLookup(img, name, vexcore_elf_hash(name), sym_type);
  if (offset != 0) return offset;

  offset = LinearLookup(img, name, sym_type);
  if (offset != 0) return offset;

  return 0;
}

#ifdef __aarch64__
  /* INFO: Struct containing information about hardware capabilities used in resolver. This
             struct information is pulled directly from the AOSP code.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/sys/ifunc.h#53
  */
  struct __ifunc_arg_t {
    unsigned long _size;
    unsigned long _hwcap;
    unsigned long _hwcap2;
  };

  /* INFO: This is a constant used in the AOSP code to indicate that the struct __ifunc_arg_t
             contains hardware capabilities.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/sys/ifunc.h#74
  */
  #define _IFUNC_ARG_HWCAP (1ULL << 62)
#elif defined(__riscv)
  /* INFO: Struct used in Linux RISC-V architecture to probe hardware capabilities.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/kernel/uapi/asm-riscv/asm/hwprobe.h#10
  */
  struct riscv_hwprobe {
    int64_t key;
    uint64_t value;
  };

  /* INFO: This function is used in the AOSP code to probe hardware capabilities on RISC-V architecture
             by calling the syscall __NR_riscv_hwprobe and passing the parameters that will filled with
             the device hardware capabilities.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/bionic/vdso.cpp#86
  */
  int __riscv_hwprobe(struct riscv_hwprobe *pairs, size_t pair_count, size_t cpu_count, unsigned long *cpus, unsigned flags) {
    register long a0 __asm__("a0") = (long)pairs;
    register long a1 __asm__("a1") = pair_count;
    register long a2 __asm__("a2") = cpu_count;
    register long a3 __asm__("a3") = (long)cpus;
    register long a4 __asm__("a4") = flags;
    register long a7 __asm__("a7") = __NR_riscv_hwprobe;

    __asm__ volatile(
      "ecall"
      : "=r"(a0)
      : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7)
    );

    return -a0;
  }

  /* INFO: This is a function pointer type that points how the signature of the __riscv_hwprobe
             function is.

     SOURCES:
      - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/include/sys/hwprobe.h#62
  */
  typedef int (*__riscv_hwprobe_t)(struct riscv_hwprobe *__pairs, size_t __pair_count, size_t __cpu_count, unsigned long *__cpus, unsigned __flags);
#endif

/* INFO: GNU ifuncs (indirect functions) are functions that does not execute the code by itself,
           but instead lead to other functions that may very according to hardware capabilities,
           or other reasons, depending of the architecture.

         This function is based on AOSP's (Android Open Source Project) code, and resolves the
           indirect symbol, leading to the correct, most appropriate for the hardware, symbol.

    SOURCES:
     - https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker.cpp#2594
     - https://android.googlesource.com/platform/bionic/+/tags/android-16.0.0_r1/libc/bionic/bionic_call_ifunc_resolver.cpp#41
*/
static ElfW(Addr) handle_indirect_symbol(ElfImg *img, ElfW(Off) offset) {
  ElfW(Addr) resolver_addr = (ElfW(Addr))((uintptr_t)img->base + offset - img->bias);

  #ifdef __aarch64__
    typedef ElfW(Addr) (*ifunc_resolver_t)(uint64_t, struct __ifunc_arg_t *);

    struct __ifunc_arg_t args = {
      ._size = sizeof(struct __ifunc_arg_t),
      ._hwcap = getauxval(AT_HWCAP),
      ._hwcap2 = getauxval(AT_HWCAP2)
    };

    return ((ifunc_resolver_t)resolver_addr)(args._hwcap | _IFUNC_ARG_HWCAP, &args);
  #elif defined(__riscv)
    typedef ElfW(Addr) (*ifunc_resolver_t)(uint64_t, __riscv_hwprobe_t, void *);

    return ((ifunc_resolver_t)resolver_addr)(getauxval(AT_HWCAP), __riscv_hwprobe, NULL);
  #else
    typedef ElfW(Addr) (*ifunc_resolver_t)(void);

    return ((ifunc_resolver_t)resolver_addr)();
  #endif
}

ElfW(Addr) getSymbAddress(ElfImg *img, const char *name) {
  unsigned char sym_type = 0;
  ElfW(Addr) offset = getSymbOffset(img, name, &sym_type);

  if (offset == 0 || !img->base) return 0;

  if (sym_type == STT_GNU_IFUNC) {
    LOGD("Resolving STT_GNU_IFUNC symbol %s", name);

    return handle_indirect_symbol(img, offset);
  }

  return (ElfW(Addr))((uintptr_t)img->base + offset - img->bias);
}

