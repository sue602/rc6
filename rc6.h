
#ifndef RC6_H
#define RC6_H

#include <stdint.h>

#define RC6_ROUNDS 20
#define RC6_KEYLEN 16
#define RC6_KR     (2*(RC6_ROUNDS+2))
#define RC6_P      0xB7E15163
#define RC6_Q      0x9E3779B9

typedef struct _RC6_KEY {
  uint32_t x[RC6_KR];
} RC6_KEY, *PRC6_KEY;

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTR(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#endif