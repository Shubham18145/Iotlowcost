# Iotlowcost
Developing code for low power consuming IOT devices
Arazi-Qi (AQ) Self-Certified Ephemeral Scheme: Arazi-Qi
(AQ) proposed a simple yet efficient self-certified ECDH scheme.
During the offline phase, all participants in the system are given a
self-certified ECDH private/public key pair by a CA. At the online
phase, any two entities with valid self-certified key pair can establish a symmetric key without requiring the transmission and verification of ECDH certificates. In Figure 1, we outline an ephemeral
AQ variant proposed by Hang et. al. in, which offers higher
security guarantees.
Eliminating Certification Overhead: In standard cryptographic suites like Arazi Qi, the sender creates an ephemeral ECDH key to
be incorporated in encryption and/or signatures. We notice that
by transforming this step into a self-certified ECDH operation, for
instance via Arazi-Qi (AQ) [2], it is possible to seamlessly eliminate
the verification/transmission overhead introduced by certificates.

AQ - Key exchange 

Arazi.cpp
Major methods
static int RNG(uint8_t *dest, unsigned size) 
uECC_set_rng(&RNG);
uECC_make_key(publicCA, privateCA, curve);
uECC_make_key(publicAlice1, privateAlice1, curve);
uECC_make_key(publicBob1, privateBob1, curve);
SHA256(publicAlice1,sizeof(publicAlice1),hash);
SHA256(publicBob1,sizeof(publicBob1),hash2);
modularMultAdd(hash, privateAlice1, privateCA, privateAlice1, curve);
modularMultAdd(hash2, privateBob1, privateCA, privateBob1, curve);
uECC_make_key(publicAlice2, privateAlice2, curve);
uECC_make_key(publicBob2, privateBob2, curve);
uECC_shared_secret2(publicBob2, privateAlice2, pointAlice2, curve);
uECC_shared_secret2(publicAlice2, privateBob2, pointBob2, curve);
uECC_shared_secret2(publicBob1, hash2, pointAlice1, curve);
EllipticAdd(pointAlice1, publicCA, pointAlice1, curve);
uECC_shared_secret2(pointAlice1, privateAlice1, pointAlice1, curve);
uECC_shared_secret2(publicAlice1, hash, pointBob1, curve);
EllipticAdd(pointBob1, publicCA, pointBob1, curve);
uECC_shared_secret2(pointBob1, privateBob1, pointBob1, curve);
EllipticAdd(pointAlice1, pointAlice2, pointAlice1, curve);
EllipticAdd(pointBob1, pointBob2, pointBob1, curve);

memcmp(pointAlice1, pointBob1, 24)
