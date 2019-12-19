//Code at https://github.com/ozgurozmen/OptimizedPKCSuite/tree/master/ATmega2560/BPV-ECDSA
//modified for performing experiments on Raspberry Pi by
//Shubham Kumar, shubham18145@iiitd.ac.in, IIIT Delhi
//ECDSA+Certificate
#include "header/uECC_vli.h"
#include "header/uECC.c"
#include "header/types.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
using namespace std;

extern "C"
{

  static int RNG(uint8_t *dest, unsigned size)
  {
    //generating bits for keys
    while (size)
    {
      uint8_t val = 0;
      int init;

      for (unsigned i = 0; i < 8; ++i)
      {
        init = (100+i)*(size);

        val = (unsigned char)(val << 1) | (init & 0x01);

      }


      *dest = val;
      ++dest;
      --size;
    }
  return 1;
  }

}  // extern "C" ends


int main()
{

  printf("Testing BPV ECDSA\n");
  uECC_set_rng(&RNG);

  const struct uECC_Curve_t * curve = uECC_secp256r1();
  uint8_t privates[1024];
  uint8_t publics[2048];


  uint8_t private1[32];
  uint8_t k[32];

  uint8_t public1[64];
  uint8_t kPub[64];
  uECC_word_t kPub2[64];
  //uECC_word_t kPub[64];
  uint8_t sum[64];

  uint8_t secret1[32];
  uint8_t secret2[32];

  uint8_t hash[32] = {0};
  uint8_t sig[64] = {0};

  clock_t a,b; // for measuring time in seconds

  a = clock();
  double totaltime = 0;
  for (unsigned i = 0; i < 32; ++i)
  {
    uECC_make_key(public1, private1, curve);
    memcpy(publics + 64*i, public1, sizeof(public1));
    memcpy(privates + 32*i, private1, sizeof(private1));
  }

  b = clock();
  unsigned long clockcycle;

  double time1 = double(b-a)/double(CLOCKS_PER_SEC);
  totaltime += time1;

  printf("Made key 1 in ");
  cout<<fixed<<setprecision(9)<<time1<<"\n";

  a = clock();

  b = clock();
  time1 = double(b-a)/double(CLOCKS_PER_SEC);
  totaltime += time1;

  printf("Made key 2 in ");
  cout<<fixed<<setprecision(9)<<time1<<"\n";

  memcpy(hash, public1, sizeof(hash));

  if (!uECC_sign(private1, hash, sizeof(hash), sig, curve))
  {
    printf("uECC_sign() failed\n");
  }
  a = clock();
  uint8_t add[64];
  uint8_t add2[64];

  uint8_t modAdd[32];
  uint8_t modAdd2[32];

  uECC_word_t kVLI[32];

  for (unsigned j = 0; j < 64; ++j)
  {
    add[j] = publics[j];
    add2[j] = publics[64 + j];
  }

  for (unsigned j = 0; j < 32; ++j)
  {
    modAdd[j] = privates[j];
    modAdd2[j] = privates[32 + j];
  }

  uECC_vli_bytesToNative(kVLI, modAdd , 32);
  EllipticAdd(add, add2, kPub, curve);
  modularAddULS(kVLI, modAdd2, kVLI,curve);

  for (unsigned i = 2; i < 32; ++i)
  {
    for (unsigned j = 0; j < 64; ++j)
    {
      add[j] = publics[(i*64) + j];
      add2[j] = kPub[j];
    }
    EllipticAdd(add, add2, kPub, curve);

    for (unsigned l = 0; l < 32; ++l)
    {
      modAdd2[l] = privates[32*i+l];
    }
    modularAddULS(kVLI, modAdd2, kVLI,curve);
  }

  uECC_vli_nativeToBytes(k, 32, kVLI);

for (unsigned i=0;i<64;i++)
  kPub2[i] = kPub[i];
  //uECC_vli_nativeToBytes(sig,32,kPub);
  uECC_vli_nativeToBytes(sig,32,kPub2);
  modularInv(k, kVLI, curve);
  uECC_word_t d[32];
  uint8_t r2[32];
  uECC_word_t s[32];

  //uint8_t s[32];
  //uECC_vli_nativeToBytes(r2, 32, kPub);

  uECC_vli_nativeToBytes(r2, 32, kPub2);
  uECC_vli_bytesToNative(d, private1, 32);

  //for (unsigned i=0;i<64;i++)
  //  kPub = (uint8_t)kPub2;

  uECC_vli_set(s, kPub2, 32);
  modularMult(private1, r2, s, curve);

  uint8_t s2[32];
  for (int i=0;i<32;i++)
    s2[i] = s[i];

  modularAdd(s2, hash, s , curve);

  uECC_vli_nativeToBytes(k, 32, kVLI);
  uECC_vli_nativeToBytes(r2, 32, s);

  modularMult(k,r2,s,curve);

  uECC_vli_nativeToBytes(sig + 32, 32, s);
  b = clock();

  time1 = double(b-a)/double(CLOCKS_PER_SEC);
  totaltime += time1;

  printf("Signing ");
  cout<<fixed<<setprecision(9)<<time1<<"\n";

  a = clock();
  // if (!uECC_verify(public1, hash, sizeof(hash), sig, curve))
  // {
  //     //printf("uECC_verify() failed for public1 and hash\n");
  // }
  //b = micros();
  b = clock();

  time1 = double(b-a)/double(CLOCKS_PER_SEC);
  totaltime += time1;

  printf("Verifying ");
  cout<<fixed<<setprecision(9)<<time1<<"\n";
  printf("Total time: ");
  cout<<fixed<<setprecision(3)<<totaltime<<"\n";

  return 0;
}
