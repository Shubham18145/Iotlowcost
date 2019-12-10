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
//#include <avr/pgmspace.h>
//#include <openssl/conf.h>
//#include <openssl/evp.h>
//#include <openssl/err.h>

AES128::AES128()
{
    rounds = 10;
    schedule = sched;
}

AES128::~AES128()
{
    clean(sched);
}

size_t AES128::keySize() const
{
    return 16;
}

bool AES128::setKey(const uint8_t *key, size_t len)
{
    if (len != 16)
        return false;

    // Copy the key itself into the first 16 bytes of the schedule.
    uint8_t *schedule = sched;
    memcpy(schedule, key, 16);

    // Expand the key schedule until we have 176 bytes of expanded key.
    uint8_t iteration = 1;
    uint8_t n = 16;
    uint8_t w = 4;
    while (n < 176) {
        if (w == 4) {
            // Every 16 bytes (4 words) we need to apply the key schedule core.
            keyScheduleCore(schedule + 16, schedule + 12, iteration);
            schedule[16] ^= schedule[0];
            schedule[17] ^= schedule[1];
            schedule[18] ^= schedule[2];
            schedule[19] ^= schedule[3];
            ++iteration;
            w = 0;
        } else {
            // Otherwise just XOR the word with the one 16 bytes previous.
            schedule[16] = schedule[12] ^ schedule[0];
            schedule[17] = schedule[13] ^ schedule[1];
            schedule[18] = schedule[14] ^ schedule[2];
            schedule[19] = schedule[15] ^ schedule[3];
        }

        // Advance to the next word in the schedule.
        schedule += 4;
        n += 4;
        ++w;
    }

    return true;
}








extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      //int init = analogRead(0);
      int init = rand()%1024;
      int count = 0;
      // while (analogRead(0) == init) {
      //   ++count;
      // }

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
/*
int generate_sha256(uint8_t *value, unsigned int n, uint8_t *hash)
{
  SHA256_CTX ctx1;
  int flag1 = SHA256_Init(&ctx1);
  int flag2 = SHA256_Update(&ctx1,value,n);
  int flag3 = SHA256_Final(hash,&ctx1);
  if (flag1==1 && flag2==1 && flag3==1)
    return 1;
  else
    return 0;

}
*/
SHA256 sha256;

// void setup() {
//   Serial.begin(115200);
//   printf("Testing ECIES\n");
//   uECC_set_rng(&RNG);
// }

int main()
{
//void loop() {
  printf("Testing ECIES\n");
  uECC_set_rng(&RNG);
  double totaltime = 0, progtime = 0;
  int loopcount = 0;
  while (true)
  {
    /* code */

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


  //unsigned long a,b,c,d;

  uECC_make_key(publicBob1, privateBob1, curve);

  //a = micros();
  a = clock();
  uECC_make_key(publicAlice1, privateAlice1, curve);
  int r = uECC_shared_secret2(publicBob1, privateAlice1, pointAlice1, curve);
  if (!r) {
    //printf("shared_secret() failed (1)\n");
    printf("shared_secret() failed (1)\n");
    return 0;
  }

  sha256.reset();
  sha256.update(pointAlice1, sizeof(pointAlice1));
  sha256.finalize(hash, sizeof(hash));

  /*
  int flag = generate_sha256(pointAlice1,sizeof(pointAlice1),hash);

  if (flag==0)
  {
    printf("SHA256 generation of pointAlice1 failed.\n");
    return 0;
  }
  */
  memcpy(keyAliceEnc, hash, sizeof(keyAliceEnc));
  memcpy(keyAliceMac, hash + 16, sizeof(keyAliceMac));

  ctraes128.setKey(keyAliceEnc, ctraes128.keySize());
  ctraes128.setIV(ivAlice, ctraes128.keySize());
  ctraes128.encrypt(ciphertext, message, sizeof(message));

  sha256.resetHMAC(keyAliceMac, sizeof(keyAliceMac));
  sha256.update(message, sizeof(message));
  sha256.finalizeHMAC(keyAliceMac, sizeof(keyAliceMac), tag, sizeof(tag));

  //b = micros();
  b = clock();

  //unsigned long clockcycle;
  //clockcycle = microsecondsToClockCycles(b-a);
  double time1 = double(b-a)/double(CLOCKS_PER_SEC);
  //printf("ECIES (Alice) in: "); //printfln(clockcycle);


  //c = micros();
  c = clock();
  r = uECC_shared_secret2(publicAlice1, privateBob1, pointBob1, curve);
  if (!r) {
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

  if (memcmp(tagBob, tag, 16) != 0) {
    printf("Message IS NOT Authenticated!\n");
  } else {
    printf("Message is Authenticated\n");
  }

  //d = micros();
  d = clock();

  //unsigned long clockcycle2;
  //clockcycle2 = microsecondsToClockCycles(d-c);
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
  }
//}
  return 0;
}
