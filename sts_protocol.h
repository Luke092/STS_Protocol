#ifndef H_STS
#define H_STS

#include "client.h"
#include "crypto.h"
#include "encodings.h"
#include "peer.h"
#include "logging.h"

/* 
 * Alice represent STS protocol initiatior
 * @return: 0 on success error code instead
 *	- (-1) Signature verification failed
 *	- (-2) Socket read/write error
 *
 * @alice: Alice peer structure
 * @rsa_bob: RSA public key of Bob
 * @socket: TCP socket
 */
int sts_alice(pPeer alice, RSA *rsa_bob, int socket);

/* 
 * Bob represent STS protocol receiver
 * @return: 0 on success error code instead
 *	- (-1) Signature verification failed
 *	- (-2) Socket read/write error
 *
 * @bob: Bob peer structure
 * @rsa_alice: RSA public key of Alice
 * @socket: TCP socket
 */
int sts_bob(pPeer bob, RSA *rsa_alice, int socket);

#endif
