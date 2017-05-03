#ifndef H_CRYPTO
#define H_CRYPTO

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <stdio.h>

#define G 2

void testBN();

DH *get_params(char *path, int len);
DH *gen_keypair(DH *params);

#endif
