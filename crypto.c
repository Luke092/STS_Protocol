#include "crypto.h"

DH *get_params(char *path, int len){
  FILE *p = fopen(path, "r");
  // Diffie-Hellman params
  DH *dh = DH_new();

  if(p == NULL){
    // no param stored
    DH_generate_parameters_ex(dh, len, G, NULL);
    p = fopen(path, "w");
    PEM_write_DHparams(p, dh);
  } else {
    // retrieve from file
    PEM_read_DHparams(p, &dh, NULL, NULL);
  }

  return dh;
}

RSA *read_rsa_key(char *pub_path, char *pri_path){
  RSA *rsa = RSA_new();

  FILE *rsa_pub_fp = fopen(pub_path, "r");
  FILE *rsa_pri_fp = NULL;
  if(pri_path != NULL){
    rsa_pri_fp = fopen(pri_path, "r");
  }
  if(rsa_pub_fp == 0 && rsa_pri_fp == 0) {
    return NULL;
  }

  // read public info
  if(rsa_pub_fp != 0){
    rsa = PEM_read_RSA_PUBKEY(rsa_pub_fp, NULL, NULL, NULL);
  }

  // read private info
  if(rsa_pri_fp != 0){
    rsa = PEM_read_RSAPrivateKey(rsa_pri_fp, &rsa, NULL, NULL);
  }

  return rsa;
}

unsigned char* get_hash_sha256(char *message, int m_len, int *r_len){
  EVP_MD_CTX *ctx =EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, message, m_len);
  unsigned char digest[EVP_MAX_MD_SIZE];
  int d_len;
  EVP_DigestFinal_ex(ctx, digest, &d_len);
  char *res = (char*) malloc(sizeof(char) * d_len);
  bcopy(digest, res, d_len);
  if(r_len != NULL){
    *r_len = d_len;
  }

  // clean up
  EVP_MD_CTX_free(ctx);

  return res;
}

unsigned char* get_hash_sha1(char *message, int m_len, int *r_len){
  EVP_MD_CTX *ctx =EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
  EVP_DigestUpdate(ctx, message, m_len);
  unsigned char digest[EVP_MAX_MD_SIZE];
  int d_len;
  EVP_DigestFinal_ex(ctx, digest, &d_len);
  char *res = (char*) malloc(sizeof(char) * d_len);
  bcopy(digest, res, d_len);
  if(r_len != NULL){
    *r_len = d_len;
  }

  // clean up
  EVP_MD_CTX_free(ctx);

  return res;
}

unsigned char* aes256_encrypt(unsigned char* key, int k_len, char *plain_text, int m_len, int *c_len){
  const int block_size = 32;
    // iv initialization
    unsigned char* iv = get_hash_sha1(key, k_len, NULL);

    // key derivation
    unsigned char* aes_key = (char*) malloc(sizeof(char) * block_size);
    PKCS5_PBKDF2_HMAC(key, k_len,
                       NULL, 0,
                       1000,
                       EVP_sha256(),
                       block_size, aes_key);

    // encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
         NULL, aes_key, iv);
    unsigned char *out = (char*) malloc(sizeof(char) * block_size + m_len);
    int o_len = 0;

    EVP_EncryptUpdate(ctx, out,
        &o_len, plain_text, m_len);

    int tmp_len;
    EVP_EncryptFinal_ex(ctx, out + o_len, &tmp_len);
    o_len += tmp_len;

    unsigned char *res = (char*) malloc(sizeof(char) * o_len);
    bcopy(out, res, o_len);
    *c_len = o_len;

    // memory clean up
    EVP_CIPHER_CTX_free(ctx);
    free(iv);
    free(aes_key);
    free(out);

    return res;
}

char* aes256_decrypt(unsigned char *key, int k_len, unsigned char *chipher_text, int c_len, int *m_len){
  const int block_size = 32;
  // iv initialization
  unsigned char* iv = get_hash_sha1(key, k_len, NULL);

  // key derivation
  unsigned char* aes_key = (char*) malloc(sizeof(char) * block_size);
  PKCS5_PBKDF2_HMAC(key, k_len,
                     NULL, 0,
                     1000,
                     EVP_sha256(),
                     block_size, aes_key);

  // decryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),
       NULL, aes_key, iv);
  unsigned char *out = (char*) malloc(sizeof(char) * block_size + c_len);
  int o_len;

  EVP_DecryptUpdate(ctx, out,
      &o_len, chipher_text, c_len);

  int tmp_len;
  EVP_DecryptFinal_ex(ctx, out + o_len, &tmp_len);
  o_len += tmp_len;

  unsigned char *res = (char*) malloc(sizeof(char) * o_len);
  bcopy(out, res, o_len);
  *m_len = o_len;

  // memory clean up
  EVP_CIPHER_CTX_free(ctx);
  free(iv);
  free(aes_key);
  free(out);

  return res;
}
