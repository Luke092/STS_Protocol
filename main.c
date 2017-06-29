#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "crypto.h"
#include "encodings.h"
#include "peer.h"
#include "sts_protocol.h"
#include "logging.h"

#include <errno.h>

#define MILLS(X) (X * 1000)
#define SEC(X) (MILLS(X) * 1000)

#define PORT 1055
void server(pPeer peer);
void client(pPeer peer);
void sts_server(int cli_socket);

void ping(pPeer peer, int socket);
void pong(pPeer peer, int socket);

pPeer g_peer;

int main(){
  // get Diffie-Hellman params
  DH *dh = get_params("./params/dh_param.pem", 1024);

  int pid = fork();

  // print debug info on standard error
  set_debug(1, stderr);

  if(pid == 0){
    // Client process, act as STS initiatior (ALICE)
    pPeer p_alice = new_peer_name("Alice");
    p_alice = set_DH(p_alice, dh); // load DH params
    RSA *rsa_alice = read_rsa_key("./alice/pub.pem", "./alice/pri.pem");
    p_alice = set_RSA(p_alice, rsa_alice); // load RSA param for signing

    // wait a second before client connection
    usleep(SEC(1));

    client(p_alice);
  } else {
    // Server Process, act as STS receiver (BOB)
    pPeer p_bob = new_peer_name("Bob");
    p_bob = set_DH(p_bob, dh); // load DH params
    RSA *rsa_bob = read_rsa_key("./bob/pub.pem", "./bob/pri.pem");
    p_bob = set_RSA(p_bob, rsa_bob); // load RSA param for signing

    server(p_bob);
  }

  return 0;
}

void server(pPeer peer){
  int sockfd = createSocket(PORT);

  switch (sockfd) {
    case -1:
      printf("Cannot create a socket\n");
      break;
    case -2:
      printf("Cannot bind a socket\n");
      break;
    default:
      printf("Server listeing on port %d\n", PORT);
  }
  if(sockfd > 0){
    g_peer = peer;
    listenLoop(sockfd, sts_server);
  }
}

void sts_server(int cli_socket){
  RSA *rsa_alice = read_rsa_key("./bob/alice.pub", NULL);
  int res = sts_bob(g_peer, rsa_alice,cli_socket);
  if(res == 0)
    pong(g_peer, cli_socket);
}

void client(pPeer peer){
  int sockfd = s_connect("127.0.0.1", PORT);
  switch (sockfd) {
    case -1:
      printf("Cannot create a socket\n");
      break;
    case -2:
      printf("Host not found\n");
      break;
    case -3:
        printf("Cannot connect to the server\n");
      break;
  }

  if(sockfd > 0){
    RSA *rsa_bob = read_rsa_key("./alice/bob.pub", NULL);
    int res = sts_alice(peer, rsa_bob, sockfd);

    if (res == 0){
      ping(peer, sockfd);
    }
  }
}

void ping(pPeer peer, int socket){
  char *reply = NULL;
  char *decrypted = NULL;
  char *str = "Ping!";
  char *msg[1];
  int c_len, m_len;
  char *encrypted = aes256_encrypt(peer->shared_key, peer->key_size, str, strlen(str), &c_len);
  msg[0] = byte_to_hex(encrypted, c_len);
  str = message_encode(msg, 1);
  while(1){
    usleep(MILLS(500));
    printf("%s> Ping!\n", peer->name);

    if(s_send(socket, str, strlen(str)) != 0){
      //TODO: send error
    }
    
    if(reply != NULL){
      free(reply);
    }
    
    if(s_receive(socket, &reply) != 0){
      //TODO: receive error
    }

    free(encrypted);
    if(decrypted != NULL){
      free(decrypted);
    }
    encrypted = hex_to_byte(message_decode(reply, NULL)[0], &c_len);
    decrypted = aes256_decrypt(peer->shared_key, peer->key_size, encrypted, c_len, &m_len);
    char *tmp = (char*) malloc(m_len + 1);
    bcopy(decrypted, tmp, m_len);
    *(tmp+m_len) = '\0';
    free(decrypted);
    decrypted = tmp;
    if(strcmp(decrypted, "Pong!") != 0){
      printf("Pong reply error!\n");
    }
  }
}

void pong(pPeer peer, int socket){
  char *reply = NULL;
  char *decrypted = NULL;
  char *str = "Pong!";
  char *msg[1];
  int c_len, m_len;
  char *encrypted = aes256_encrypt(peer->shared_key, peer->key_size, str, strlen(str), &c_len);
  msg[0] = byte_to_hex(encrypted, c_len);
  str = message_encode(msg, 1);
  while(1){
    if(reply != NULL){
      free(reply);
    }
    
    if(s_receive(socket, &reply) != 0){
      //TODO: receive error
    }

    free(encrypted);
    if(decrypted != NULL){
      free(decrypted);
    }
    char *decode = message_decode(reply, NULL)[0];
    encrypted = hex_to_byte(decode, &c_len);
    decrypted = aes256_decrypt(peer->shared_key, peer->key_size, encrypted, c_len, &m_len);
    char *tmp = (char*) malloc(m_len + 1);
    bcopy(decrypted, tmp, m_len);
    *(tmp+m_len) = '\0';
    free(decrypted);
    decrypted = tmp;
    if(strcmp(decrypted, "Ping!") == 0){
      usleep(MILLS(250));
      printf("%s> Pong!\n", peer->name);

      if(s_send(socket, str, strlen(str)) != 0){
        //TODO: receive error
      }

    } else {
      printf("Ping Error!\n");
    }
  }
}
