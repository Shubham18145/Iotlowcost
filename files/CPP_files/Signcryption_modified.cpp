#include "uECC_vli.h"
#include "uECC.h"
#include "uECC.c"
#include "types.h"
#include <stdio.h>
#include "SHA256.cpp"
//#include <SHA256.h>
//#include "sha256.cpp"

//#include <openssl/sha.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <cmath>

#include "AES.h"
//#include "AES128.cpp"
//#include "CTR.h"
//#include "CTR.h"
#include "CTR.cpp"

extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = rand()%1024;
      int count = 0;

      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

}  // extern "C"


CTR<AES128> ctraes128;
SHA256 sha256;


/*int generate_sha256(uint8_t *value, uint8_t *hash)
{
  SHA256_CTX ctx1;
  int flag1 = SHA256_Init(&ctx1);
  int flag2 = SHA256_Update(&ctx1,value,sizeof(value));
  int flag3 = SHA256_Final(hash,&ctx1);
  if (flag1==1 && flag2==1 && flag3==1)
    return 1;
  else
    return 0;

}*/

/*void setup() {
  Serial.begin(115200);
  Serial.print("Testing Signcryption\n");
  uECC_set_rng(&RNG);
}*/

int main()
{
  printf("Testing Signcryption\n");
  uECC_set_rng(&RNG);
  double totaltime = 0, progtime = 0;
  int loopcount = 0;

  while(true) {
    const struct uECC_Curve_t * curve = uECC_secp192r1();

    uint8_t privateAlice1[24];
    uint8_t privateAlice2[24];


    uint8_t privateBob1[24];

    uint8_t publicAlice1[48];

    uint8_t publicBob1[48];

    uint8_t hash[32] = {0};
    uint8_t hash2[32] = {0};

    uint8_t keyAliceEnc[16] = {0};
    uint8_t keyAliceSign[16] = {0};
    uint8_t ivAlice[16] = {0};
    uint8_t keyBobEnc[16] = {0};
    uint8_t keyBobSign[16] = {0};
    uint8_t ivBob[16] = {0};

    uint8_t message[32] = {0};
    uint8_t messageBob[32] = {0};

    uint8_t ciphertext[32];

    uint8_t tag[24] = {0};
    uint8_t s[24] = {0};
    uint8_t tagBob[24] = {0};

    uint8_t pointAlice1[48];
    uint8_t pointBob1[48];


    clock_t a,b,c,d; // for measuring time in seconds

    uECC_make_key(publicBob1, privateBob1, curve);
    uECC_make_key(publicAlice1, privateAlice1, curve);


    a = clock();
    uECC_make_private_key(privateAlice2,curve);

    int r = uECC_shared_secret2(publicBob1, privateAlice2, pointAlice1, curve);
    if (!r) {
      printf("shared_secret() failed (1)\n");
      return 0;
    }

    sha256.reset();
    sha256.update(pointAlice1, sizeof(pointAlice1));
    sha256.finalize(hash, sizeof(hash));

    memcpy(keyAliceEnc, hash, sizeof(keyAliceEnc));
    memcpy(keyAliceSign, hash + 16, sizeof(keyAliceSign));

    ctraes128.setKey(keyAliceEnc, ctraes128.keySize());
    ctraes128.setIV(ivAlice, ctraes128.keySize());
    ctraes128.encrypt(ciphertext, message, sizeof(message));

    sha256.resetHMAC(keyAliceSign, sizeof(keyAliceSign));
    sha256.update(message, sizeof(message));
    sha256.finalizeHMAC(keyAliceSign, sizeof(keyAliceSign), tag, sizeof(tag));

    modularAdd2(privateAlice1, tag, s, curve);
    modularInv2(s, s, curve);

    modularMult2(privateAlice2, s, s, curve);
    b = clock();
    double time1 = double(b-a)/double(CLOCKS_PER_SEC);
    //Serial.print("Signcryption (Alice) in: "); Serial.println(clockcycle);



    c = clock();
    modularMult2(s, privateBob1, s, curve);
    r = uECC_compute_public_key(tag, pointBob1, curve);
    if (!r) {
      printf("shared_secret() failed (1)\n");
      return 0;
    }
    EllipticAdd(pointBob1, publicAlice1, pointBob1, curve);
    r = uECC_shared_secret2(pointBob1, s, pointBob1, curve);
    if (!r) {
      printf("shared_secret() failed (1)\n");
      return 0;
    }

    sha256.reset();
    sha256.update(pointBob1, sizeof(pointBob1));
    sha256.finalize(hash2, sizeof(hash2));

    memcpy(keyBobEnc, hash2, sizeof(keyBobEnc));
    memcpy(keyBobSign, hash2 + 16, sizeof(keyBobSign));

    ctraes128.setKey(keyAliceEnc, ctraes128.keySize());
    ctraes128.setIV(ivAlice, ctraes128.keySize());
    ctraes128.decrypt(messageBob, ciphertext, sizeof(messageBob));

    sha256.resetHMAC(keyBobSign, sizeof(keyBobSign));
    sha256.update(messageBob, sizeof(messageBob));
    sha256.finalizeHMAC(keyBobSign, sizeof(keyBobSign), tagBob, sizeof(tagBob));


    if (memcmp(tagBob, tag, 16) != 0) {
      printf("Message IS NOT Authenticated!\n");
    } else {
      printf("Message is Authenticated\n");
    }
    d = clock();
    double time2 = double(d-c)/double(CLOCKS_PER_SEC);
    //printf("ECIES (Bob) in: "); printfln(clockcycle2);
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
    //cout<<fixed<<setprecision(3)<<totaltime<<" seconds\n";
    printf("%.4f  seconds\n",progtime+totaltime);
    //printf("Signcryption (Bob) in: "); Serial.println(clockcycle2);

  }
  return 0;
}
