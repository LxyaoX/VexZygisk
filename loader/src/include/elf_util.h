#ifndef ELF_UTIL_H
#define ELF_UTIL_H

#include <stdbool.h>

#include <link.h>
#include <sys/types.h>

#define SHT_GNU_HASH 0x6ffffff6

/* bionic's <elf.h> provides ELF_ST_TYPE, glibc does not; kept guarded so the
   host tests compile against either libc. */
#ifndef ELF_ST_TYPE
  #define ELF_ST_TYPE(info) ((info) & 0xf)
#endif

typedef struct {
  char *elf;
  void *base;
  ElfW(Ehdr) *header;
  size_t size;
  off_t bias;
  ElfW(Shdr) *section_header;

  ElfW(Shdr) *dynsym;
  ElfW(Off) dynsym_offset;
  ElfW(Sym) *dynsym_start;
  size_t dynsym_count;
  ElfW(Shdr) *strtab;
  ElfW(Off) symstr_offset;
  void *strtab_start;

  uint32_t nbucket_;
  uint32_t *bucket_;
  uint32_t *chain_;
  /* The chain length the section header vouches for (SysV nchain): the lookup
     walks the chain with the symbol count as bound, so the count has to fit. */
  uint32_t chain_len_;

  uint32_t gnu_nbucket_;
  uint32_t gnu_symndx_;
  uint32_t gnu_bloom_size_;
  uint32_t gnu_shift2_;
  uintptr_t *gnu_bloom_filter_;
  uint32_t *gnu_bucket_;
  uint32_t *gnu_chain_;
  /* How many chain entries the section can hold: the GNU chain's length is not
     in the header, and the lookup bounds its walk by the symbol count. */
  uint32_t gnu_chain_len_;

  ElfW(Shdr) *symtab;
  ElfW(Off) symtab_offset;
  size_t symtab_size;
  size_t symtab_count;
  ElfW(Sym) *symtab_start;
  ElfW(Off) symstr_offset_for_symtab;
  /* So a symbol name offset can be checked against the table it reads from. */
  size_t symstr_size_for_symtab;

  /* Mini-debug info (.gnu_debugdata): an LZMA-compressed ELF holding a full
     .symtab for otherwise stripped system libraries. */
  uint8_t *debugdata;
  ElfW(Sym) *dd_symtab_start;
  size_t dd_symtab_count;
  const char *dd_strtab;
  size_t dd_strtab_size;

  ElfW(Sym) **symtabs_;
  size_t symtabs_count_;
} ElfImg;

void ElfImg_destroy(ElfImg *img);

ElfImg *ElfImg_create(const char *elf, void *base);

bool ElfImg_load_symbols(ElfImg *img);

const char *getSymbName(ElfImg *img, ElfW(Sym) *sym);

ElfW(Addr) getSymbAddress(ElfImg *img, const char *name);

#endif /* ELF_UTIL_H */
