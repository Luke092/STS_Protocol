#ifndef H_STS
#define H_STS

#include "client.h"
#include "crypto.h"
#include "encodings.h"
#include "peer.h"
#include "logging.h"

// Alice represent STS protocol initiatior
int sts_alice(pPeer alice, RSA *rsa_bob, int socket);

// Bob represent STS protocol receiver
int sts_bob(pPeer bob, RSA *rsa_alice, int socket);

#endif
