#ifndef H_CRYPTO
#define H_CRYPTO

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <strings.h>

#define G 2

void testBN();

DH *get_params(char *path, int len);
RSA *read_rsa_key(char *pub_path, char *pri_path);

// create a hash of a message using SHA-256
unsigned char* get_hash_sha256(char *message, int m_len, int *r_len);
// create a hash of a message using SHA-1
unsigned char* get_hash_sha1(char *message, int m_len, int *r_len);

// AES-256 CBC encryption functions
unsigned char* aes256_encrypt(unsigned char* key, int k_len, char *plain_text, int m_len, int *c_len);
char* aes256_decrypt(unsigned char *key, int k_len, unsigned char *chipher_text, int c_len, int *m_len);

#endif
