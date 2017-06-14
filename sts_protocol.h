#ifndef H_STS
#define H_STS

#include "client.h"
#include "crypto.h"
#include "encodings.h"
#include "peer.h"

// Alice represent STS protocol initiatior
pPeer sts_alice(pPeer alice, RSA *rsa_bob, int socket);

// Bob represent STS protocol receiver
pPeer sts_bob(pPeer bob, RSA *rsa_alice, int socket);

#endif
