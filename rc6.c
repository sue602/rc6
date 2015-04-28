
#include "rc6.h"

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTR(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

void rc6_set_key (RC6_KEY *key, uint8_t *K, size_t keylen)
{  
  uint32_t i, j, k, A, B, T, L[8], *kptr=(uint32_t*)K; 
  
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
    uint32_t  w[4], t,u,i;
    uint32_t *in, *out;
    
    in  = (uint32_t*)input;
    out = (uint32_t*)output;
    
    for (i=0; i<4; i++)
      w[i]=in[i];
    
    w[1] += key->x[0];
    w[3] += key->x[1];
    
    for (i=2; i<42; i+=2) {
      t = ROTL(w[1] * (2 * w[1] + 1), 5);
      u = ROTL(w[3] * (2 * w[3] + 1), 5);
      w[0] = ROTL(w[0] ^ t, u) + key->x[i];
      w[2] = ROTL(w[2] ^ u, t) + key->x[i + 1];
      // shift w
      t=w[0];
      w[0]=w[1];
      w[1]=w[2];
      w[2]=w[3];
      w[3]=t;
    }
    for (i=0; i<4; i++)
      out[i] = w[i];
    
    out[0] += key->x[42];
    out[2] += key->x[43];
}

void rc6_decrypt(RC6_KEY *key, void *input, void *output)
{   
    uint32_t w[4], t,u,i;
    uint32_t *in, *out;
    
    in  = (uint32_t*)input;
    out = (uint32_t*)output;
    
    for (i=0; i<4; i++)
      w[i]=in[i];
    
    w[0] -= key->x[42];
    w[2] -= key->x[43];

    for (i=40; i>0; i-=2) {
      u = ROTL(w[2] * (2*w[2] + 1), 5);     
      t = ROTL(w[0] * (2*w[0] + 1), 5);       
      w[1] = ROTR(w[1] - key->x[i + 1], t) ^ u; 
      w[3] = ROTR(w[3] - key->x[i], u) ^ t;
      // shift w
      t=w[3];
      w[3]=w[2];
      w[2]=w[1];
      w[1]=w[0];
      w[0]=t;
    }
    for (i=0; i<4; i++)
      out[i]=w[i];
    
    out[1] -= key->x[0];
    out[3] -= key->x[1];      
}
