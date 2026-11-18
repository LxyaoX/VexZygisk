#ifndef ZYGISK_H
#define ZYGISK_H

#include <stddef.h>

extern void *start_addr;
extern size_t block_size;

void hook_functions(void);

#endif /* ZYGISK_H */
