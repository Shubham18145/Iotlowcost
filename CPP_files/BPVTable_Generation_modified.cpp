//Code at https://github.com/ozgurozmen/OptimizedPKCSuite/tree/master/ATmega2560/BPVTableGeneration
//modified for performing experiments on Raspberry Pi by
//Shubham Kumar, shubham18145@iiitd.ac.in, IIIT Delhi
//Code for generating BPV Table (not for calculating time taken)
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
                init = rand()%1024;
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
    printf("BPV Table generation ");
    uECC_set_rng(&RNG);

    srand(time(0));
    const struct uECC_Curve_t * curve = uECC_secp192r1();

    uint8_t privateAlice1[24];
    uint8_t privateAlice2[24];

    uint8_t privateBob2[24];

    uint8_t publicAlice1[48];
    uint8_t publicAlice2[48];

    uint8_t publicBob2[48];

    uint8_t hash[24] = {0};
    uint8_t hash2[24] = {0};

    uint8_t pointAlice1[48];
    uint8_t pointBob1[48];

    uint8_t pointAlice2[48];
    uint8_t pointBob2[48];

    long randNumber;
    uint8_t privateBob1[24] = {0xEB, 0xF9, 0x3D, 0xE3, 0x1B, 0xCC, 0x7D, 0x87, 0xE5, 0x16, 0x31, 0x73, 0xBB, 0x14, 0xA1, 0x2E, 0xBC, 0xE1, 0x36, 0xBA, 0xB, 0x3F, 0x47, 0xA1};
    uint8_t publicBob1[48] = {0x9D, 0x3F, 0x58, 0x94, 0x5F, 0x13, 0xFE, 0xEC, 0x99, 0x1A, 0xE3, 0xEC, 0x12, 0xE2, 0x20, 0xDD, 0x81, 0x96, 0x9C, 0x76, 0xC8, 0x5, 0xC, 0xCD, 0xE0, 0x36, 0x43, 0x2A, 0x3C, 0x2A, 0xA0, 0x0, 0x57, 0xAD, 0x1F, 0xC, 0x4D, 0x66, 0x26, 0x37, 0x38, 0xA0, 0xFD, 0x1A, 0x67, 0xD3, 0x48, 0xFD};

    uint8_t privateCA[24] = {0xB6, 0xE, 0x87, 0xB8, 0xDB, 0x7F, 0xB4, 0x3C, 0xBB, 0xDE, 0x1E, 0x1E, 0xCC, 0xFE, 0x44, 0x1, 0x26, 0xD4, 0xBB, 0xEE, 0xE8, 0x70, 0x18, 0x3E};
    uint8_t publicCA[48] = {0x9F, 0xD2, 0x62, 0xED, 0x71, 0x19, 0xEA, 0xF4, 0x64, 0x25, 0xCF, 0x22, 0x34, 0x7C, 0x90, 0xBA, 0xC6, 0x92, 0x24, 0x31, 0xBC, 0x9, 0x1E, 0x56, 0x55, 0x39, 0xC8, 0xAE, 0xBF, 0x7A, 0x79, 0x8B, 0xA3, 0xF2, 0xE5, 0x39, 0x5A, 0x48, 0xC9, 0x27, 0x48, 0x96, 0xEC, 0x4F, 0x68, 0x9C, 0xDB, 0xF9};


    unsigned long a,b,c,d;

    sha256.reset();
    sha256.update(publicBob1, sizeof(publicBob1));
    sha256.finalize(hash2, sizeof(hash2));

    uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
    EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);


    printf("const PROGMEM  uint8_t BPVTable[] = { ");
    for (unsigned i = 0; i < 160; ++i)
    {

        uECC_make_key(publicAlice1, privateAlice1, curve);
        for (unsigned j = 0; j < 24; ++j)
        {
            if (i!=159 && j!=23)
                printf("0x%02x, ",privateAlice1[j]);
            else
                printf("0x%02x ",privateAlice1[j]);
        }

        int r = uECC_shared_secret2(pointAlice1, privateAlice1, pointBob1, curve);
        if (!r)
        {
            printf("shared_secret() failed (1)\n");
            return 0;
          }
        for (unsigned j = 0; j < 48; ++j)
        {
            if (j!=47)
                printf("0x%02x, ",pointBob1[j]);
            else
                printf("0x%02x ",pointBob1[j]);
        }

    }
    printf(" };\n");
    return 0;
}
