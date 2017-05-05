#include "peer.h"

pPeer new_peer(){
  pPeer p = (pPeer) malloc(sizeof(struct peer));
  p->name = NULL;
  p->dh = NULL;
  p->rsa = NULL;
  p->shared_key = NULL;
  return p;
}

pPeer new_peer_name(char *name){
  pPeer p = new_peer();
  p->name = name;
  return p;
}

pPeer set_DH(pPeer p, DH *dh){
  p->dh = dh;
  return p;
}

pPeer set_DH_fp(pPeer p, char *path){
  DH *dh = get_params(path, 1024);
  p->dh = dh;
  return p;
}

pPeer set_RSA(pPeer p, RSA *rsa){
  p->rsa = rsa;
  return p;
}

pPeer derive_key(pPeer p, BIGNUM *pub){
  int size = DH_size(p->dh);
  unsigned char *key = (char *) malloc(sizeof(char) * size);
  DH_compute_key(key, pub, p->dh);
  p->shared_key = key;
}

pPeer derive_key_hex(pPeer p, char *hex_pub){
  BIGNUM *pub = BN_new();
  int res = BN_hex2bn(&pub, hex_pub);
  if(res != 0){
    p = derive_key(p, pub);
  }
  return p;
}
