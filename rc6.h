
#ifndef RC6_H
#define RC6_H

#include <stdint.h>

#define RC6_ROUNDS 20
#define RC6_P      0xB7E15163
#define RC6_Q      0x9E3779B9

#ifdef _MSC_VER

#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define rotr(x,n) _lrotr(x,n)
#define rotl(x,n) _lrotl(x,n)

#else

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

#endif

#define bswap(x)    (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)

typedef struct _RC6_KEY {
  uint32_t x[(RC6_ROUNDS+2)*2];
} RC6_KEY, *PRC6_KEY;

#endif