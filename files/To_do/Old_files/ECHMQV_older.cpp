//Code at https://github.com/ozgurozmen/OptimizedPKCSuite/tree/master/ATmega2560/ECHMQV
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



SHA256 sha256;

int main()
{
	printf("Testing Ephemeral ECHMQV\n");
	uECC_set_rng(&RNG);
	double totaltime = 0, progtime = 0;
	int loopcount = 0;
	while(true)
	{
	  const struct uECC_Curve_t * curve = uECC_secp192r1();
	  uint8_t privateCA[25];
	  uint8_t private1[25];
	  uint8_t private2[25];

	  uint8_t publicCA[48];
	  uint8_t public1[48];
	  uint8_t public2[48];

	  uint8_t hash[24] = {0};
	  uint8_t hash2[24] = {0};
	  uint8_t sig[48] = {0};
	  uint8_t sig2[48] = {0};

	  uint8_t key1[48];
	  uint8_t key2[48];

	  clock_t a,b,c,d; // for measuring time in seconds

	  uint8_t privateEph1[25];
	  uint8_t privateEph2[25];

	  uint8_t publicEph1[48];
	  uint8_t publicEph2[48];

	  uint8_t hashD[24] = {0};
	  uint8_t hashE[24] = {0};

	  uECC_make_key(publicCA, privateCA, curve);

	  uECC_make_key(public1, private1, curve);
	  uECC_make_key(public2, private2, curve);

	  sha256.reset();
	  sha256.update(public1, sizeof(public1));
	  sha256.finalize(hash, sizeof(hash));

	  sha256.reset();
	  sha256.update(public2, sizeof(public2));
	  sha256.finalize(hash2, sizeof(hash2));

	  //  memcpy(hash, public1, sizeof(hash));
	  //  memcpy(hash2, public2, sizeof(hash2));

	  if (!uECC_sign(privateCA, hash, sizeof(hash), sig, curve))
    {
		    printf("uECC_sign() failed\n");
	  }

	  if (!uECC_sign(privateCA, hash2, sizeof(hash2), sig2, curve))
    {
		    printf("uECC_sign() failed\n");
	  }


	  if (!uECC_verify(publicCA, hash, sizeof(hash), sig, curve))
    {
		    printf("uECC_verify() failed for publicCA and hash\n");
	  }

	  if (!uECC_verify(publicCA, hash2, sizeof(hash2), sig2, curve))
    {
		    printf("uECC_verify() failed for publicCA and hash2\n");
	  }
	  //Serial.print("CA signature is verified\n");
	  //printf("CA signature is verified\n");

	//  int r = uECC_shared_secret(public2, private1, key1, curve);
	//  if (!r) {
	//    Serial.print("shared_secret() failed (1)\n");
	//    return;
	//  }
	//  //printHex(key1,24);
	//
	//  r = uECC_shared_secret(public1, private2, key2, curve);
	//  if (!r) {
	//    Serial.print("shared_secret() failed (1)\n");
	//    return;
	//  }


	  //a = micros();
	  a = clock();
	  uECC_make_key(publicEph1, privateEph1, curve);

	  sha256.reset();
	  sha256.update(publicEph1, sizeof(publicEph1));
	  sha256.finalize(hashD, sizeof(hashD));

	  sha256.reset();
	  sha256.update(publicEph2, sizeof(publicEph2));
	  sha256.finalize(hashE, sizeof(hashE));

	  //b = micros();
	  b = clock();
	  //clockcycle = microsecondsToClockCycles(b-a);
	  double time1 = double(b-a)/double(CLOCKS_PER_SEC);

	  //c = micros();
	  c = clock();
	  uECC_make_key(publicEph2, privateEph2, curve);

	  sha256.reset();
	  sha256.update(publicEph1, sizeof(publicEph1));
	  sha256.finalize(hashD, sizeof(hashD));

	  sha256.reset();
	  sha256.update(publicEph2, sizeof(publicEph2));
	  sha256.finalize(hashE, sizeof(hashE));

	  //d = micros();
	  d = clock();
	  //clockcycle2 = microsecondsToClockCycles(d-c);
	  double time2 = double(d-c)/double(CLOCKS_PER_SEC);

	//  memcpy(hashD, publicEph1, sizeof(hashD));
	//  memcpy(hashE, publicEph2, sizeof(hashE));

	  //a = micros();
	  a = clock();
	  int r = uECC_shared_secret2(public2, hashE, key1, curve);
	  if (!r) {
		//Serial.print("shared_secret() failed (1)\n");
		printf("shared_secret() failed (1)\n");
		return 0;
	  }

	  EllipticAdd(key1, publicEph2, key1, curve);

	  modularMultAdd(hashD, private1, privateEph1, privateEph1, curve);
	  r = uECC_shared_secret2(key1, privateEph1, key1, curve);
	  if (!r) {
		//Serial.print("shared_secret() failed (1)\n");
		printf("shared_secret() failed (1)\n");
		return 0;
	  }
	  //b = micros();
	  b = clock();
	  //clockcycle = clockcycle + microsecondsToClockCycles(b-a);
	  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);
	  //Serial.print("Ephemeral ECHMQV: "); Serial.println(clockcycle);
	  //print("Ephemeral ECHMQV: ");
	  //Serial.println(clockcycle);

	  //c = micros();
	  c = clock();
	  r = uECC_shared_secret2(public1, hashD, key2, curve);
	  if (!r) {
		//Serial.print("shared_secret() failed (1)\n");
		printf("shared_secret() failed (1)\n");
		return 0;
	  }

	  EllipticAdd(key2, publicEph1, key2, curve);
	  modularMultAdd(hashE, private2, privateEph2, privateEph2, curve);

	  r = uECC_shared_secret2(key2, privateEph2, key2, curve);
	  if (!r) {
		//Serial.print("shared_secret() failed (1)\n");
		printf("shared_secret() failed (1)\n");
		return 0;
	  }
	  //d = micros();
	  d = clock();
	  //clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
	  time2 = time2+double(d-c)/double(CLOCKS_PER_SEC);
	  //Serial.print("Ephemeral ECHMQV: "); Serial.println(clockcycle2);
	  totaltime += time1+time2;
	  loopcount +=1 ;
	  printf("Total time taken till iteration: %d\n",loopcount);

	  //totaltime = totaltime*1000000;
          long integraltime = 0;
          if (totaltime>1.0)
          {
            integraltime = long(totaltime);
	    progtime += integraltime;
	    totaltime = totaltime-integraltime;
           }
	  printf("%.4f seconds\n",progtime+totaltime);

	  if (memcmp(key1, key2, 24) != 0) {
		//Serial.print("Shared secrets are not identical!\n");
		printf("Shared secrets are not identical!\n");
	  } else {
		//Serial.print("Shared secrets are identical\n");
		printf("Shared secrets are identical\n");
	  }
	  if (progtime+totaltime>100)
	     break;
	}
	return 0;
}
