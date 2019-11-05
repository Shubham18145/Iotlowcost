#include "uECC.c"
//#include <uECC_vli.h>
//#include <uECC.h>
#include "types.h"
#include <string.h>
#include <openssl/sha.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      //int init = analogRead(0);
	  int init;
	  init = i*100+i*i;
	  //cin>>init;//between 0 and 1023
	  init = ((init%1024)+1024)%1024;
      //init = rand()%1024;//randomly generating numbers between 0 and 1023
	  int count = 0;
      //while (analogRead(0) == init) {
       // ++count;
      //}

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



//SHA256 sha256;

//void setup() {
  //Serial.begin(115200);
  //Serial.print("Testing Ephemeral ECHMQV\n");
  //uECC_set_rng(&RNG);
//}

int main()
{
	printf("Testing Ephemeral ECHMQV\n");
	uECC_set_rng(&RNG);
	double totaltime = 0;
	int loopcount = 0;
	//void loop() {
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

	  //unsigned long a,b,c,d, clockcycle, clockcycle2;
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

	  //sha256.reset();
	  //sha256.update(public1, sizeof(public1));
	  //sha256.finalize(hash, sizeof(hash));
	  SHA256(public1,sizeof(public1),hash);

	  //sha256.reset();
	  //sha256.update(public2, sizeof(public2));
	  //sha256.finalize(hash2, sizeof(hash2));

	  SHA256(public2,sizeof(public2),hash2);
		
	//  memcpy(hash, public1, sizeof(hash));
	//  memcpy(hash2, public2, sizeof(hash2));

	  if (!uECC_sign(privateCA, hash, sizeof(hash), sig, curve)) {
		 printf("uECC_sign() failed\n");
		 //Serial.print("uECC_sign() failed\n");
	  }

	  if (!uECC_sign(privateCA, hash2, sizeof(hash2), sig2, curve)) {
		 printf("uECC_sign() failed\n");
		 //Serial.print("uECC_sign() failed\n");
	  }
	  

	  if (!uECC_verify(publicCA, hash, sizeof(hash), sig, curve)) {
		 printf("uECC_verify() failed\n");
		 //Serial.print("uECC_verify() failed\n");
	  } 
	  //Serial.print("CA signature is verified\n");
	  //printf("CA signature is verified\n");

	  if (!uECC_verify(publicCA, hash2, sizeof(hash2), sig2, curve)) {
		 printf("uECC_verify() failed\n");
	  } 
	  //Serial.print("CA signature is verified\n");
	  printf("CA signature is verified\n");
	  
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

	  //sha256.reset();
	  //sha256.update(publicEph1, sizeof(publicEph1));
	  //sha256.finalize(hashD, sizeof(hashD));

	  SHA256(publicEph1,sizeof(publicEph1),hashD);
	  
	  //sha256.reset();
	  //sha256.update(publicEph2, sizeof(publicEph2));
	  //sha256.finalize(hashE, sizeof(hashE));
	  
	  SHA256(publicEph2,sizeof(publicEph2),hashE);
	  
	  //b = micros();
	  b = clock();
	  //clockcycle = microsecondsToClockCycles(b-a);
	  double time1 = double(b-a)/double(CLOCKS_PER_SEC);

	  //c = micros();
	  c = clock();
	  uECC_make_key(publicEph2, privateEph2, curve);

	  //sha256.reset();
	  //sha256.update(publicEph1, sizeof(publicEph1));
	  //sha256.finalize(hashD, sizeof(hashD));

	  SHA256(publicEph1,sizeof(publicEph1),hashD);
		
	  //sha256.reset();
	  //sha256.update(publicEph2, sizeof(publicEph2));
	  //sha256.finalize(hashE, sizeof(hashE));
	 
	  SHA256(publicEph2,sizeof(publicEph2),hashE);
	 
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
		return;
	  }

	  EllipticAdd(key1, publicEph2, key1, curve);

	  modularMultAdd(hashD, private1, privateEph1, privateEph1, curve);
	  r = uECC_shared_secret2(key1, privateEph1, key1, curve);
	  if (!r) {
		//Serial.print("shared_secret() failed (1)\n");
		print("shared_secret() failed (1)\n");
		return;
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
		Serial.print("shared_secret() failed (1)\n");
		printf("shared_secret() failed (1)\n");
		return;
	  }

	  EllipticAdd(key2, publicEph1, key2, curve);
	  modularMultAdd(hashE, private2, privateEph2, privateEph2, curve);
	  
	  r = uECC_shared_secret2(key2, privateEph2, key2, curve);
	  if (!r) {
		//Serial.print("shared_secret() failed (1)\n");
		printf("shared_secret() failed (1)\n");
		return;
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

	  cout<<fixed<<setprecision(3)<<totaltime<<"\n";

	  if (memcmp(key1, key2, 24) != 0) {
		//Serial.print("Shared secrets are not identical!\n");
		printf("Shared secrets are not identical!\n");
	  } else {
		//Serial.print("Shared secrets are identical\n");
		printf("Shared secrets are identical\n");
	  }

	}
	return 0;
}


