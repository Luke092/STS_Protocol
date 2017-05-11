#ifndef H_PEER
#define H_PEER

#include "crypto.h"

typedef struct peer{
  char *name; // optional identifier for the peer
  DH *dh; // DH param and keypair
  RSA *rsa; // used for signing messages
  unsigned int key_size;
  unsigned char *shared_key; // ephemeral key derived from the protocol
} * pPeer;

pPeer new_peer();
pPeer new_peer_name(char *name);
pPeer set_DH(pPeer p, DH *dh);
pPeer set_DH_fp(pPeer p, char *f);
pPeer set_RSA(pPeer p, RSA *rsa);
pPeer derive_key(pPeer p, BIGNUM *pub);
pPeer derive_key_hex(pPeer p, char *hex_pub);

#endif
