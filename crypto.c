#include "crypto.h"

DH *gen_keypair(DH *params){
  DH_generate_key(params);
  return params;
}

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
