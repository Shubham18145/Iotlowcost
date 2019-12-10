//Code at https://github.com/ozgurozmen/OptimizedPKCSuite/tree/master/ATmega2560/Arazi
//modified for performing experiments on Raspberry Pi by
//Shubham Kumar, shubham18145@iiitd.ac.in, IIIT Delhi
#include "header/uECC_vli.h"
#include "header/uECC.h"
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

  printf("Testing Arazi\n");
  uECC_set_rng(&RNG);
  double totaltime = 0, progtime = 0;
  int loopcount = 0;
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

  uint8_t sig[48] = {0};
  uint8_t hash3[24] = {0};
  uint8_t sig2[48] = {0};
  uint8_t hash4[24] = {0};
  uint8_t sig3[48] = {0};
  uint8_t hash5[24] = {0};

  clock_t a,b,c,d; // for measuring time in seconds

  int status1 = uECC_make_key(publicCA, privateCA, curve);
  int status2 = uECC_make_key(publicAlice1, privateAlice1, curve);
  int status3 = uECC_make_key(publicBob1, privateBob1, curve);

  // if (status1==0)
  //   printf("uECC_make_key(publicCA, privateCA, curve) failed\n");
  // if (status2==0)
  //   printf("uECC_make_key(publicAlice1, privateAlice1, curve) failed\n");
  // if (status3==0)
  //   printf("uECC_make_key(publicBob1, privateBob1, curve) failed\n");

  if (!uECC_sign(privateAlice1, hash3, sizeof(hash3), sig, curve))
  {
    printf("\nuECC_sign() Alice failed\n");
  }

  if (!uECC_verify(publicAlice1, hash3, sizeof(hash3), sig, curve))
  {
    printf("uECC_verify() Alice failed\n");
  }

  if (!uECC_sign(privateBob1, hash4, sizeof(hash4), sig2, curve))
  {
    printf("\nuECC_sign() Bob failed\n");
  }

  if (!uECC_verify(publicBob1, hash4, sizeof(hash4), sig2, curve))
  {
    printf("uECC_verify() Bob failed\n");
  }

  if (!uECC_sign(privateCA, hash5, sizeof(hash5), sig3, curve))
  {
    printf("\nuECC_sign() CA failed\n");
  }

  if (!uECC_verify(publicCA, hash5, sizeof(hash5), sig3, curve))
  {
    printf("uECC_verify() CA failed\n");
  }
    /*else
    {
      printf("\nVerify CA successful. \n");
    }*/


/*
    cout<<"publicca\n";

    for (int i=0;i<48;i++)
    {
      cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)publicCA[i]<<" ";
    }
    cout<<"\nprivateca\n";
    for (int i=0;i<24;i++)
    {
      cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)privateCA[i]<<" ";
    }
    cout<<"\npublicalice1\n";
    for (int i=0;i<48;i++)
    {
      cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)publicAlice1[i]<<" ";
    }
    cout<<"\nprivatealice1\n";
    for (int i=0;i<24;i++)
    {
      cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)privateAlice1[i]<<" ";
    }
    cout<<"\npublicbob1\n";
    for (int i=0;i<48;i++)
    {
      cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)publicBob1[i]<<" ";
    }
    cout<<"\nprivatebob1\n";
    for (int i=0;i<24;i++)
    {
      cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)privateBob1[i]<<" ";
    }
    cout<<"\n";
*/

  a = clock();

  sha256.reset();
  sha256.update(publicAlice1, sizeof(publicAlice1));
  sha256.finalize(hash, sizeof(hash));

  b = clock();
  double time1 = double(b-a)/double(CLOCKS_PER_SEC);

  c = clock();
  sha256.reset();
  sha256.update(publicBob1, sizeof(publicBob1));
  sha256.finalize(hash2, sizeof(hash2));

  d = clock();
	double time2 = double(d-c)/double(CLOCKS_PER_SEC);

  modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
  modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);

  a = clock();
  int status4 = uECC_make_key(publicAlice2, privateAlice2, curve);
  if (status4==0)
    printf("uECC_make_key(publicAlice2, privateAlice2, curve) failed\n");

  b = clock();
  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);

  c = clock();
  int status5 =  uECC_make_key(publicBob2, privateBob2, curve);
  if (status5==0)
    printf("uECC_make_key(publicBob2, privateBob2, curve) failed\n");

  d = clock();
  time2 = time2+double(d-c)/double(CLOCKS_PER_SEC);


  a = clock();
  int r = uECC_shared_secret2(publicBob2, privateAlice2, pointAlice2, curve);
  b = clock();
  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);

  if (!r) {
	printf("shared_secret() failed (1)\n");
    return 0;
  }

  c = clock();
  r = uECC_shared_secret2(publicAlice2, privateBob2, pointBob2, curve);
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
  EllipticAdd(pointAlice1, pointAlice2, pointAlice1, curve);
  b = clock();
  time1 = time1+double(b-a)/double(CLOCKS_PER_SEC);

  c = clock();

  EllipticAdd(pointBob1, pointBob2, pointBob1, curve);


  d = clock();
  time2 = time2+double(d-c)/double(CLOCKS_PER_SEC);


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
  //printf("Totaltime: %.6f seconds\n",totaltime);

  //cout<<"PointAlice1: "<<pointAlice1<<"\n";
  //cout<<"PointBob1: "<<pointBob1<<"\n";
/*
  printf("PointAlice1: \n");
  for (int i=0;i<24;i++)
  {
    printf("%02x  ",(unsigned int)(unsigned char)pointAlice1[i]);
      //cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)pointAlice1[i]<<"  ";
  }
  printf("\n---------------------------PointBob1: \n");
  for (int i=0;i<24;i++)
  {
    printf("%02x  ",(unsigned int)(unsigned char)pointBob1[i]);

      //cout<<hex<<setfill('0')<<setw(2)<<(unsigned int)(unsigned char)pointBob1[i]<<"  ";
  }
*/

  if (memcmp(pointAlice1, pointBob1, 24) != 0) {
    printf("Shared secrets are not identical!\n");
    //return 0;
  } else {
    printf("Shared secrets are identical\n");

  }
if (progtime+totaltime>100)
break;
 }
	return 0;
}
