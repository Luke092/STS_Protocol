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

void ping(pPeer peer, int socket);
void pong(pPeer peer, int socket);

pPeer g_bob;

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
  DH_get0_key(g_bob->dh, (const BIGNUM **)&pub, NULL);
  char *str_pub_key = BN_bn2hex(pub);

  // signing
  unsigned char* pub_keys = str_concat(str_pub_key, alice_dh_pub_str);
  int d_hash;
  unsigned char* hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys),&d_hash);

  unsigned char* sign_pub_keys = (char*) malloc(RSA_size(g_bob->rsa));
  unsigned int sign_len;
  RSA_sign(NID_sha1, hash_pub_keys, d_hash,
            sign_pub_keys, &sign_len, g_bob->rsa);

  // clean temp memory
  free(pub_keys);
  free(hash_pub_keys);

  // encryption with shared_key
  int e_k_len = 0;
  unsigned char* e_k = aes256_encrypt(g_bob->shared_key, g_bob->key_size,
    sign_pub_keys, sign_len, &e_k_len);

  free(sign_pub_keys);

  char *message[2];
  message[0] = str_pub_key;
  message[1] = byte_to_hex(e_k, e_k_len);
  char *encoded_str = message_encode(message, 2);

  // send g^y and E_k(S_b(SHA256(g^y,g^x))) to alice
  s_send(cli_socket, encoded_str, strlen(encoded_str));

  // get E_k(S_a(SHA256(g^x,g^y))) from alice
  free(enc_str);
  enc_str = s_receive(cli_socket);
  free(dec_str);
  dec_str = message_decode(enc_str, NULL);

  // verify E_k(S_b(SHA256(g^y,g^x)))
  RSA *rsa_alice = read_rsa_key("./bob/alice.pub", NULL);
  e_k_len = 0;
  free(e_k);
  e_k = hex_to_byte(dec_str[0], &e_k_len);

  // decrypt
  sign_len = 0;
  sign_pub_keys = aes256_decrypt(g_bob->shared_key, g_bob->key_size,
    e_k, e_k_len, &sign_len);

  // verify sign
  pub_keys = str_concat(alice_dh_pub_str, str_pub_key);
  hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys),&d_hash);

  int verify = RSA_verify(NID_sha1, hash_pub_keys, d_hash,
    sign_pub_keys, sign_len, rsa_alice);
  if(verify != 1){
    printf("Bob> Alice's signature error!!!\n");
    exit(-1);
  }

  printf("Bob> Alice Trusted!\n");

  printf("Bob> Ephemeral key created! Starting communication...\n");

  ping(g_bob, cli_socket);
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
    DH_get0_key(peer->dh, (const BIGNUM **)&pub, NULL);
    char *str_pub_key = BN_bn2hex(pub);
    char *message[1];
    message[0] = str_pub_key;
    char *encoded_str = message_encode(message, 1);

    // send g^x to Bob
    s_send(sockfd, encoded_str, strlen(encoded_str));

    // get g^y and E_k(S_b(SHA256(g^y,g^x))) from Bob
    encoded_str = s_receive(sockfd);
    char **dec_str = message_decode(encoded_str, NULL);
    char* bob_dh_pub_str = dec_str[0];
    BIGNUM *bob_dh_pub = BN_new();
    BN_hex2bn(&bob_dh_pub, bob_dh_pub_str);

    // calculate shared key
    peer = derive_key(peer, bob_dh_pub);

    // verify E_k(S_b(SHA256(g^y,g^x)))
    RSA *rsa_bob = read_rsa_key("./alice/bob.pub", NULL);
    int e_k_len = 0;
    char *e_k = hex_to_byte(dec_str[1], &e_k_len);

    // decrypt
    int sign_len = 0;
    unsigned char *sign_pub_keys = aes256_decrypt(peer->shared_key, peer->key_size,
      e_k, e_k_len, &sign_len);

    // verify sign
    unsigned char* pub_keys = str_concat(bob_dh_pub_str, str_pub_key);
    int d_hash;
    unsigned char* hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys),&d_hash);

    int verify = RSA_verify(NID_sha1, hash_pub_keys, d_hash,
      sign_pub_keys, sign_len, rsa_bob);
    if(verify != 1){
      printf("Alice> Bob's signature error!!!\n");
      exit(-1);
    }

    printf("Alice> Bob Trusted!\n");

    free(pub_keys);
    free(hash_pub_keys);
    pub_keys = str_concat(str_pub_key, bob_dh_pub_str);
    hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys), &d_hash);

    //signing
    free(sign_pub_keys);
    sign_pub_keys = (char*) malloc(RSA_size(peer->rsa));
    RSA_sign(NID_sha1, hash_pub_keys, d_hash,
              sign_pub_keys, &sign_len, peer->rsa);

    // clean temp memory
    free(pub_keys);
    free(hash_pub_keys);

    // encryption with shared_key
    e_k_len = 0;
    free(e_k);
    e_k = aes256_encrypt(peer->shared_key, peer->key_size,
      sign_pub_keys, sign_len, &e_k_len);

    free(sign_pub_keys);

    // send E_k(S_a(SHA256(g^x,g^y)))
    message[0] = byte_to_hex(e_k, e_k_len);
    free(encoded_str);
    encoded_str = message_encode(message, 1);
    s_send(sockfd, encoded_str, strlen(encoded_str));

    printf("Alice> Ephemeral key created! Starting communication...\n");
    pong(peer, sockfd);

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
    s_send(socket, str, strlen(str));
    if(reply != NULL){
      free(reply);
    }
    reply = s_receive(socket);
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
    reply = s_receive(socket);
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
      s_send(socket, str, strlen(str));
    } else {
      printf("Ping Error!\n");
    }
  }
}
