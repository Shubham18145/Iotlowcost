//Code at https://github.com/ozgurozmen/OptimizedPKCSuite/tree/master/ATmega2560/ECIES
//modified for performing experiments on Raspberry Pi by
//Shubham Kumar, shubham18145@iiitd.ac.in, IIIT Delhi
#include "header/uECC_vli.h"
#include "header/uECC.c"
#include "header/types.h"
#include <stdio.h>
#include "header/SHA256.cpp"
#include <string.h>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "header/AES128.cpp"
#include "header/CTR.cpp"
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


CTR<AES128> ctraes128;
SHA256 sha256;

int main()
{
  printf("Testing ECIES\n");
  uECC_set_rng(&RNG);
  double totaltime = 0, progtime = 0;
  int loopcount = 0;
  while (true)
  {

    clock_t a,b,c,d; // for measuring time in seconds
    const struct uECC_Curve_t * curve = uECC_secp192r1();

    uint8_t privateAlice1[24];
    uint8_t privateBob1[24];
    uint8_t publicAlice1[48];
    uint8_t publicBob1[48];

    uint8_t hash[32] = {0};
    uint8_t hash2[32] = {0};

    uint8_t keyAliceEnc[16] = {0};
    uint8_t keyAliceMac[16] = {0};
    uint8_t ivAlice[16] = {0};
    uint8_t keyBobEnc[16] = {0};
    uint8_t keyBobMac[16] = {0};
    uint8_t ivBob[16] = {0};

    uint8_t message[32] = {0};
    uint8_t messageBob[32] = {0};

    uint8_t ciphertext[32];

    uint8_t tag[16] = {0};
    uint8_t tagBob[16] = {0};

    uint8_t pointAlice1[48];
    uint8_t pointBob1[48];

    uECC_make_key(publicBob1, privateBob1, curve);

    a = clock();
    uECC_make_key(publicAlice1, privateAlice1, curve);
    int r = uECC_shared_secret2(publicBob1, privateAlice1, pointAlice1, curve);
    if (!r)
    {
      printf("shared_secret() failed (1)\n");
      return 0;
    }

    sha256.reset();
    sha256.update(pointAlice1, sizeof(pointAlice1));
    sha256.finalize(hash, sizeof(hash));

    memcpy(keyAliceEnc, hash, sizeof(keyAliceEnc));
    memcpy(keyAliceMac, hash + 16, sizeof(keyAliceMac));

    ctraes128.setKey(keyAliceEnc, ctraes128.keySize());
    ctraes128.setIV(ivAlice, ctraes128.keySize());
    ctraes128.encrypt(ciphertext, message, sizeof(message));

    sha256.resetHMAC(keyAliceMac, sizeof(keyAliceMac));
    sha256.update(message, sizeof(message));
    sha256.finalizeHMAC(keyAliceMac, sizeof(keyAliceMac), tag, sizeof(tag));

    b = clock();

    double time1 = double(b-a)/double(CLOCKS_PER_SEC);

    c = clock();
    r = uECC_shared_secret2(publicAlice1, privateBob1, pointBob1, curve);
    if (!r)
    {
      printf("shared_secret() failed (1)\n");
      return 0;
    }

    sha256.reset();
    sha256.update(pointBob1, sizeof(pointBob1));
    sha256.finalize(hash2, sizeof(hash2));

    memcpy(keyBobEnc, hash2, sizeof(keyBobEnc));
    memcpy(keyBobMac, hash2 + 16, sizeof(keyBobMac));

    ctraes128.setKey(keyBobEnc, ctraes128.keySize());
    ctraes128.setIV(ivBob, ctraes128.keySize());
    ctraes128.decrypt(messageBob, ciphertext, sizeof(messageBob));

    sha256.resetHMAC(keyBobMac, sizeof(keyBobMac));
    sha256.update(messageBob, sizeof(messageBob));
    sha256.finalizeHMAC(keyBobMac, sizeof(keyBobMac), tagBob, sizeof(tagBob));

    if (memcmp(tagBob, tag, 16) != 0)
    {
      printf("Message IS NOT Authenticated!\n");
    }
    else
    {
      printf("Message is Authenticated\n");
    }

    d = clock();

    double time2 = double(d-c)/double(CLOCKS_PER_SEC);

    totaltime += time1+time2;
    loopcount +=1 ;
    printf("Total time taken till iteration %d :",loopcount);
    long integraltime = 0;
    if (totaltime > 1.0)
    {
      integraltime = long(totaltime);
      progtime += integraltime;
      totaltime = totaltime-integraltime;
    }

    printf("%.4f  seconds\n",progtime+totaltime);
    if (progtime+totaltime>100)
      break;
  }

  return 0;
}
