

// RC6 in C
// Odzhan

#ifndef RC6_H
#define RC6_H

#include <stdint.h>

#define RC6_ROUNDS 20
#define RC6_KR     (2*(RC6_ROUNDS+2))
#define RC6_P      0xB7E15163
#define RC6_Q      0x9E3779B9

typedef struct _RC6_KEY {
  uint32_t x[RC6_KR];
} RC6_KEY;

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTR(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#ifdef __cplusplus
{
#endif

  void rc6_setkey (RC6_KEY*, uint8_t*, size_t);
  void rc6_encrypt (RC6_KEY*, void*, void*);
  void rc6_decrypt (RC6_KEY*, void*, void*);

#ifdef __cplusplus
}
#endif

#endif