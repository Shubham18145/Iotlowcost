#include "uECC_vli.h"
#include "uECC.c"
#include "types.h"
#include <stdio.h>
//#include <SHA256.h>
//#include "sha256.cpp"
#include <openssl/sha.h>
#include <string.h>
#include <iostream>
#include <iomanip>
using namespace std;
//#include <avr/pgmspace.h>

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
	 //init = i*100+i*i;
	  //cin>>init;//between 0 and 1023
	  //init = ((init%1024)+1024)%1024;
      init = rand()%1024;//randomly generating numbers between 0 and 1023
      //while (analogRead(0) == init) {
       // ++count;
      //}
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

//SHA256 sha256;

//void setup() {
  //Serial.begin(115200);
  //Serial.print("Testing Arazi\n");
  //uECC_set_rng(&RNG);
//}

int main(){
	
//void loop() {
  printf("Testing Arazi\n");
  uECC_set_rng(&RNG);
  while (true){
  const struct uECC_Curve_t * curve = uECC_secp192r1();
  uint8_t privateCA[24];
  uint8_t publicCA[48];
  
  uint8_t privateAlice1[24];
  uint8_t privateAlice2[24];

  uint8_t privateBob1[24];
  uint8_t privateBob2[24];

  uint8_t publicAlice1[48];
  uint8_t publicAlice2[48];

  uint8_t publicBob1[48];
  uint8_t publicBob2[48];

  uint8_t hash[24] = {0};
  uint8_t hash2[24] = {0};

  uint8_t pointAlice1[48];
  uint8_t pointBob1[48];

  uint8_t pointAlice2[48];
  uint8_t pointBob2[48];

  //unsigned long a,b,c,d;
	clock_t a,b,c,d; // for measuring time in seconds

  uECC_make_key(publicCA, privateCA, curve);
  uECC_make_key(publicAlice1, privateAlice1, curve);
  uECC_make_key(publicBob1, privateBob1, curve);
  
  //a = micros();
  a = clock();
  //unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
  
  /*sha256.reset();
  sha256.update(publicAlice1, sizeof(publicAlice1));
  sha256.finalize(hash, sizeof(hash));
  */
  SHA256(publicAlice1,sizeof(publicAlice1),hash);
  //b = micros();
  b = clock();
  //unsigned long clockcycle;
  //clockcycle = microsecondsToClockCycles(b-a);
  double time1 = double(b-a)/double(CLOCKS_PER_SEC);
  
	
  //c = micros();
  c = clock();
  /*sha256.reset();
  sha256.update(publicBob1, sizeof(publicBob1));
  sha256.finalize(hash2, sizeof(hash2));
  */
  SHA256(publicBob1,sizeof(publicBob1),hash2);
  
  //d = micros();
  d = clock();
  //unsigned long clockcycle2;
  //clockcycle2 = microsecondsToClockCycles(d-c);
	double time2 = double(d-c)/double(CLOCKS_PER_SEC);
  
  
//  memcpy(hash, publicAlice1, sizeof(hash));
//  memcpy(hash2, publicBob1, sizeof(hash2));

  modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
  modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);


 // modularAdd2(privateAlice1, privateCA, privateAlice1, curve);
  //modularAdd2(privateBob1, privateCA, privateBob1, curve);

//  modularMult2(privateAlice1, hash, privateAlice1, curve);
//  modularMult2(privateBob1, hash2, privateBob1, curve);


  //a = micros();
  a = clock();
  uECC_make_key(publicAlice2, privateAlice2, curve);
  //b = micros();
  b = clock();
  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);
  //clockcycle = clockcycle + microsecondsToClockCycles(b-a);
//  Serial.print("Made key 1 in "); Serial.println(clockcycle);

  //c = micros();
  c = clock();
  uECC_make_key(publicBob2, privateBob2, curve);
  //d = micros();
  d = clock();
  time2 = time2+double(d-c)/double(CLOCKS_PER_SEC);
  //clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
//  Serial.print("Made key 2 in "); Serial.println(clockcycle2);

  a = clock();
  //a = micros();
  int r = uECC_shared_secret2(publicBob2, privateAlice2, pointAlice2, curve);
  //b = micros();
  b = clock();
  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);
  //clockcycle = clockcycle + microsecondsToClockCycles(b-a);
  if (!r) {
    //Serial.print("shared_secret() failed (1)\n");
	printf("shared_secret() failed (1)\n");
    return 0;
  }
  
  c = clock();
  //c = micros();
  r = uECC_shared_secret2(publicAlice2, privateBob2, pointBob2, curve);
  //d = micros();
  //clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
  d = clock();
  time2 = time2+double(d-c)/double(CLOCKS_PER_SEC);
  if (!r) {
    printf("shared_secret() failed (1)\n");
    return 0;
  }
  
  

  r = uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
  if (!r) {
    printf("shared_secret() failed (1)\n");
    return 0;
  }
  EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);
  r = uECC_shared_secret2(pointAlice1, privateAlice1, pointAlice1, curve);
  if (!r) {
    printf("shared_secret() failed (1)\n");
    return 0;
  }
  
  r = uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
  if (!r) {
    printf("shared_secret() failed (1)\n");
    return 0;
  }
  EllipticAdd(pointBob1, publicCA, pointBob1, curve);
  r = uECC_shared_secret2(pointBob1, privateBob1, pointBob1, curve);

  a = clock();
  //a = micros();
  EllipticAdd(pointAlice1, pointAlice2, pointAlice1, curve);
  //b = micros();
  //clockcycle = clockcycle + microsecondsToClockCycles(b-a);
  b = clock();
  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);
  
  printf("Arazi in: "); 
  cout<<fixed<<setprecision(9)<<time1<<"\n";


  //c = micros();
  c = clock();
  EllipticAdd(pointBob1, pointBob2, pointBob1, curve);
  //d = micros();
  //clockcycle2 = clockcycle2 + microsecondsToClockCycles(d-c);
  d = clock();
  time2 = time2+double(d-c)/double(CLOCKS_PER_SEC);
  printf("Arazi in: "); 
  cout<<fixed<<setprecision(9)<<time2<<"\n";

  if (memcmp(pointAlice1, pointBob1, 24) != 0) {
    printf("Shared secrets are not identical!\n");
  } else {
    printf("Shared secrets are identical\n");
  }
 }
	return 0;
//}
}
