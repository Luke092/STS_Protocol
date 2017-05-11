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
  FILE *rsa_pri_fp = fopen(pri_path, "r");
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

  //RSA_print_fp(stdout, rsa, 0);
  //printf("\n");
  return rsa;
}

char* get_hash_sha256(char *message, int *r_len){
  EVP_MD_CTX *ctx =EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, message, strlen(message));
  char *digest[EVP_MAX_MD_SIZE];
  int d_len;
  EVP_DigestFinal_ex(ctx, digest, &d_len);
  char *res = (char*) malloc(sizeof(char) * d_len);
  bcopy(digest, res, d_len);
  if(r_len != NULL){
    *r_len = d_len;
  }
  return res;
}
