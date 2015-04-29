

// RC6 in C
// Odzhan

#include "rc6.h"

void rc6_setkey (RC6_KEY *key, uint8_t *K, size_t keylen)
{  
  uint32_t i, j, k, A, B, L[8], *kptr=(uint32_t*)K; 
  
  // initialize L with key
  for (i=0; i<keylen/4; i++) {
    L[i] = kptr[i];
  }
  
  A=RC6_P;
  
  // initialize S with constants
  for (i=0; i<RC6_KR; i++) {
    key->x[i] = A;
    A += RC6_Q;
  }
  
  A=B=i=j=k=0;
  
  // mix with key
  for (; k < RC6_KR*3; k++)
  { 
    A = key->x[i] = ROTL(key->x[i] + A+B, 3);  
    B = L[j]      = ROTL(L[j] + A+B, A+B);
    
    i++;
    i %= RC6_KR;
    
    j++;
    j %= keylen/4;
  } 
}

void rc6_encrypt (RC6_KEY *key, void* input, void* output)
{
  uint32_t  A, B, C, D, t, u, i;
  uint32_t *in, *out, *k;
  
  in  = (uint32_t*)input;
  out = (uint32_t*)output;
  k   = (uint32_t*)key->x;
  
  // load plaintext
  A=in[0];
  B=in[1];
  C=in[2];
  D=in[3];
  
  // add first 2 words in key
  B += *k++;
  D += *k++;
  
  // for number of rounds
  for (i=0; i<RC6_ROUNDS; i++) {
    t = ROTL(B * (2 * B + 1), 5);
    u = ROTL(D * (2 * D + 1), 5);
    A = ROTL(A ^ t, u) + *k++;
    C = ROTL(C ^ u, t) + *k++;
    // swap
    t=A;
    A=B;
    B=C;
    C=D;
    D=t;
  }
  
  // add last 2 words in key
  A += *k++;
  C += *k++;
  
  // save
  out[0]=A;
  out[1]=B;
  out[2]=C;
  out[3]=D;
}

void rc6_decrypt(RC6_KEY *key, void *input, void *output)
{   
  uint32_t A, B, C, D, t, u, i, j;
  uint32_t *in, *out, *k;

  in  = (uint32_t*)input;
  out = (uint32_t*)output;
  k   = (uint32_t*)&key->x[RC6_KR];
  j   = RC6_KR - 4;
  
  // load ciphertext
  A=in[0];
  B=in[1];
  C=in[2];
  D=in[3];
   
  // sub last 2 words in key
  C -= key->x[43];
  A -= key->x[42];

  // for each round
  for (i=RC6_ROUNDS; i>0; i--, j -= 2) {
    t = ROTL(A * (2 * A + 1), 5);
    u = ROTL(C * (2 * C + 1), 5);            
    B = ROTR(B - key->x[j+1], t) ^ u;
    D = ROTR(D - key->x[j], u) ^ t;
    // swap
    t=D;
    D=C;
    C=B;
    B=A;
    A=t;
  }
  
  // sub first 2 words
  D -= key->x[1];
  B -= key->x[0];

  // save
  out[0]=A;
  out[1]=B;
  out[2]=C;
  out[3]=D;
}
