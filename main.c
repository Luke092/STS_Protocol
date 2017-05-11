#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "crypto.h"
#include "encodings.h"
#include "peer.h"

#define MILLS(X) (X * 1000)
#define SEC(X) (MILLS(X) * 1000)

#define PORT 1055

void bob(pPeer peer);
void alice(pPeer peer);
void sts_server(int cli_socket);

pPeer g_bob;

//DEBUG
void print_bytes(unsigned char* key, int len){
  int i = 0;
  for (i = 0; i < len; i++){
    printf("%.2X ", key[i]);
  }
  printf("\n");
}

// string concatenation
char* string_concat(char* s1, char* s2){
    int size1 = strlen(s1);
    int size2 = strlen(s2);
    char* res = (char*) malloc(sizeof(char) * size1 + size2 + 1);

    char* pt_r = res;

    char* pt_s = s1;
    for(int i = 0; i < size1; i++){
        *pt_r = *pt_s;
        pt_r++;
        pt_s++;
    }
    pt_s = s2;
    for(int i = 0; i < size2; i++){
        *pt_r = *pt_s;
        pt_r++;
        pt_s++;
    }
    *pt_r = '\0';

    return res;
}

int main(){
  // get Diffie-Hellman params
  DH *dh = get_params("./params/dh_param.pem", 1024);

  int pid = fork();

  if(pid == 0){
    pPeer p_alice = new_peer_name("Alice");
    p_alice = set_DH(p_alice, dh); // load DH params
    RSA *rsa_alice = read_rsa_key("./alice/pub.pem", "./alice/pri.pem");
    p_alice = set_RSA(p_alice, rsa_alice); // load RSA param for signing
    // wait a second before client connection
    usleep(SEC(1));
    alice(p_alice);
  } else {
    pPeer p_bob = new_peer_name("Bob");
    p_bob = set_DH(p_bob, dh); // load DH params
    RSA *rsa_bob = read_rsa_key("./bob/pub.pem", "./bob/pri.pem");
    p_bob = set_RSA(p_bob, rsa_bob); // load RSA param for signing
    bob(p_bob);
  }

  return 0;
}

void bob(pPeer peer){
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
    g_bob = peer;
    listenLoop(sockfd, sts_server);
  }
}

void sts_server(int cli_socket){
  // get g^x from Alice
  char* enc_str = s_receive(cli_socket);
  char** dec_str = message_decode(enc_str, NULL);
  char* alice_dh_pub_str = dec_str[0];
  BIGNUM *alice_dh_pub = BN_new();
  BN_hex2bn(&alice_dh_pub, alice_dh_pub_str);

  // generate y and g^y
  DH_generate_key(g_bob->dh);

  // calculate shared key
  g_bob = derive_key(g_bob, alice_dh_pub);

  BIGNUM *pub = BN_new();
  DH_get0_key(g_bob->dh, &pub, NULL);
  char *str_pub_key = BN_bn2hex(pub);

  // signing
  unsigned char* pub_keys = string_concat(str_pub_key, alice_dh_pub_str);
  int d_hash;
  unsigned char* hash_pub_keys = get_hash_sha256(pub_keys, &d_hash);
  unsigned char* sign_pub_keys = (char*) malloc(RSA_size(g_bob->rsa));
  unsigned int sign_len;
  int res = RSA_sign(NID_sha1, hash_pub_keys, strlen(hash_pub_keys),
            sign_pub_keys, &sign_len, g_bob->rsa);
  char* sign_pub_keys_hex = byte_to_hex(sign_pub_keys, sign_len);

  // encryption with shared_key
  //TODO: encryption

  char *message[2];
  message[0] = str_pub_key;
  message[1] = sign_pub_keys_hex;
  char *encoded_str = message_encode(message, 2);

  // send g^y and E_k(S_b(SHA256(g^y,g^x))) to alice
  s_send(cli_socket, encoded_str, strlen(encoded_str));
}

void alice(pPeer peer){
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
    // generate x and g^x
    DH_generate_key(peer->dh);

    BIGNUM *pub = BN_new();
    DH_get0_key(peer->dh, &pub, NULL);
    char *str_pub_key = BN_bn2hex(pub);
    char *message[1];
    message[0] = str_pub_key;
    char *encoded_str = message_encode(message, 1);

    // send g^x to Bob
    s_send(sockfd, encoded_str, strlen(encoded_str));

    // get g^y from Bob
    encoded_str = s_receive(sockfd);
    char **dec_str = message_decode(encoded_str, NULL);
    char* bob_dh_pub_str = dec_str[0];
    BIGNUM *bob_dh_pub = BN_new();
    BN_hex2bn(&bob_dh_pub, bob_dh_pub_str);

    // calculate shared key
    peer = derive_key(peer, bob_dh_pub);
  }
}
