#ifndef H_CRYPTO
#define H_CRYPTO

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>

#define G 2

void testBN();

DH *get_params(char *path, int len);
RSA *read_rsa_key(char *pub_path, char *pri_path);

// create a hash of a message using SHA-256
char* get_hash_sha256(char *message, int *r_len);

#endif
