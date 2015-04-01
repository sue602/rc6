
#include "rc6.h"

#define f_rnd(i, a, b, c, d) \
    u = rotl(d * (d + d + 1), 5); \
    t = rotl(b * (b + b + 1), 5); \
    a = rotl(a ^ t, u) + key->x[i]; \
    c = rotl(c ^ u, t) + key->x[i + 1]

#define i_rnd(i, a, b, c, d) \
    u = rotl(d * (d + d + 1), 5);       \
    t = rotl(b * (b + b + 1), 5);       \
    c = rotr(c - key->x[i + 1], t) ^ u;  \
    a = rotr(a - key->x[i], u) ^ t

void rc6_set_key (RC6_KEY *key, void* in, size_t key_len)
{
    uint32_t  i, j, k, a, b, l[8], t;
    uint32_t *in_key=(uint32_t*)in;
    
    key->x[0] = 0xb7e15163;
    
    for (k=1; k<44; ++k)
      key->x[k] = key->x[k - 1] + 0x9e3779b9;
    
    for(k = 0; k < key_len / 4; ++k)
      l[k] = in_key[k];
    
    t = (key_len / 4) - 1;
    a = b = i = j = 0;
    
    for (k=0; k<132; ++k)
    {
      a = rotl(key->x[i] + a + b, 3); 
      b += a;
      b = rotl(l[j] + b, b);
      key->x[i] = a; l[j] = b;
      i = (i == 43) ? 0 : i + 1; 
      j = (j ==  t) ? 0 : j + 1;
    }
}

void rc6_encrypt (RC6_KEY *key, void* in, void* out)
{
    uint32_t  a,b,c,d,t,u,i;
    uint32_t *in_blk, *out_blk;
    
    in_blk=(uint32_t*)in;
    out_blk=(uint32_t*)out;
    
    a = in_blk[0]; 
    b = in_blk[1] + key->x[0];
    c = in_blk[2]; 
    d = in_blk[3] + key->x[1];

    for (i=2; i<42; i+=2) {
      f_rnd(i, a, b, c, d);
      t=a;
      a=b;
      b=c;
      c=d;
      d=t;
    }
    out_blk[0] = a + key->x[42]; 
    out_blk[1] = b;
    out_blk[2] = c + key->x[43]; 
    out_blk[3] = d;
}

void rc6_decrypt(RC6_KEY *key, void *in, void *out)
{   
    uint32_t  a,b,c,d,t,u,i;
    uint32_t *in_blk, *out_blk;
    
    in_blk=(uint32_t*)in;
    out_blk=(uint32_t*)out;
    
    a = in_blk[0] - key->x[42];
    b = in_blk[1];
    c = in_blk[2] - key->x[43];
    d = in_blk[3]; 

    for (i=40; i>0; i-=2) {
      i_rnd(i, d, a, b, c);
      t=d;
      d=c;
      c=b;
      b=a;
      a=t;
    }
    out_blk[0] = a;
    out_blk[1] = b - key->x[0];
    out_blk[2] = c;
    out_blk[3] = d - key->x[1];      
}

#ifdef RC6_TEST

char *test_keys[] = 
{ "00000000000000000000000000000000",
  "0123456789abcdef0112233445566778",
  "00000000000000000000000000000000"
  "0000000000000000",
  "0123456789abcdef0112233445566778"
  "899aabbccddeeff0",
  "00000000000000000000000000000000"
  "00000000000000000000000000000000",
  "0123456789abcdef0112233445566778"
  "899aabbccddeeff01032547698badcfe" };

char *test_plaintexts[] =
{ "00000000000000000000000000000000",
  "02132435465768798a9bacbdcedfe0f1",
  "00000000000000000000000000000000",
  "02132435465768798a9bacbdcedfe0f1",
  "00000000000000000000000000000000",
  "02132435465768798a9bacbdcedfe0f1" };
            
char *test_ciphertexts[] =
{ "8fc3a53656b1f778c129df4e9848a41e",
  "524e192f4715c6231f51f6367ea43f18",
  "6cd61bcb190b30384e8a3f168690ae82",
  "688329d019e505041e52e92af95291d4",
  "8f5fbd0510d15fa893fa3fda6e857ec2",
  "c8241816f0d7e48920ad16a1674e5d48"};
  
size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
} 

void run_tests (void)
{
  size_t i, plen, clen, klen;
  uint8_t p[32], c1[32], c2[32], k[32];
  RC6_KEY rc6_key;
  
  for (i=0; i<sizeof (test_keys)/sizeof(char*); i++)
  {
    memset (p, 0, sizeof (p));
    memset (c1, 0, sizeof (c1));
    memset (c2, 0, sizeof (c2));
    memset (k, 0, sizeof (k));
    
    klen=hex2bin (k, test_keys[i]);
    clen=hex2bin (c1, test_ciphertexts[i]);
    plen=hex2bin (p, test_plaintexts[i]);
    
    rc6_set_key (&rc6_key, k, klen);
    rc6_encrypt (&rc6_key, p, c2);
    
    if (memcmp (c1, c2, clen)==0) {
      printf ("\nPassed test #%i", (i+1));
    } else {
      printf ("\nFailed test #%i", (i+1));
    }
  }
}

int main (int argc, char *argv[])
{
  run_tests();
  return 0;
}

#endif