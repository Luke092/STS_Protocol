#include "sts_protocol.h"

int sts_alice(pPeer alice, RSA *rsa_bob, int socket){
  // generate x and g^x
  DH_generate_key(alice->dh);

  BIGNUM *pub = BN_new();
  DH_get0_key(alice->dh, (const BIGNUM **)&pub, NULL);
  char *str_pub_key = BN_bn2hex(pub);
  char *message[1];
  message[0] = str_pub_key;
  char *encoded_str = message_encode(message, 1);

  // send g^x to Bob
  if(s_send(socket, encoded_str, strlen(encoded_str)) != 0){
    shutdown(socket, SHUT_RDWR);
    close(socket);
    return -2;
  }

  // get g^y and E_k(S_b(SHA256(g^y,g^x))) from Bob
  if(s_receive(socket, &encoded_str) != 0){
    shutdown(socket, SHUT_RDWR);
    close(socket);
    return -2;
  }

  char **dec_str = message_decode(encoded_str, NULL);
  char* bob_dh_pub_str = dec_str[0];
  BIGNUM *bob_dh_pub = BN_new();
  BN_hex2bn(&bob_dh_pub, bob_dh_pub_str);

  // calculate shared key
  alice = derive_key(alice, bob_dh_pub);

  // verify E_k(S_b(SHA256(g^y,g^x)))
  int e_k_len = 0;
  char *e_k = hex_to_byte(dec_str[1], &e_k_len);

  // decrypt
  int sign_len = 0;
  unsigned char *sign_pub_keys = aes256_decrypt(alice->shared_key, alice->key_size,
    e_k, e_k_len, &sign_len);

  // verify sign
  unsigned char* pub_keys = str_concat(bob_dh_pub_str, str_pub_key);
  int d_hash;
  unsigned char* hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys),&d_hash);

  int verify = RSA_verify(NID_sha1, hash_pub_keys, d_hash,
    sign_pub_keys, sign_len, rsa_bob);
  if(verify != 1){
    write_log("Alice> Bob's signature error!!!");
    //close connection
    shutdown(socket, SHUT_RDWR);
    close(socket);
    
    write_log("Alice> Connection closed!");

    return -1; // Signature verification filure
  }

  write_log("Alice> Bob Trusted!");

  free(pub_keys);
  free(hash_pub_keys);
  pub_keys = str_concat(str_pub_key, bob_dh_pub_str);
  hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys), &d_hash);

  //signing
  free(sign_pub_keys);
  sign_pub_keys = (char*) malloc(RSA_size(alice->rsa));
  RSA_sign(NID_sha1, hash_pub_keys, d_hash,
            sign_pub_keys, &sign_len, alice->rsa);

  // clean temp memory
  free(pub_keys);
  free(hash_pub_keys);

  // encryption with shared_key
  e_k_len = 0;
  free(e_k);
  e_k = aes256_encrypt(alice->shared_key, alice->key_size,
    sign_pub_keys, sign_len, &e_k_len);

  free(sign_pub_keys);

  // send E_k(S_a(SHA256(g^x,g^y)))
  message[0] = byte_to_hex(e_k, e_k_len);
  free(encoded_str);
  encoded_str = message_encode(message, 1);

  if(s_send(socket, encoded_str, strlen(encoded_str)) != 0){
    shutdown(socket, SHUT_RDWR);
    close(socket);
    return -2;
  }

  write_log("Alice> Ephemeral key created!");
  //Log SharedKey
  write_log_bytes("Alice EphemeralKey:", alice->shared_key, alice->key_size);
  
  return 0; // STS succeded
}

int sts_bob(pPeer bob, RSA *rsa_alice, int socket){
  // get g^x from Alice
  char* enc_str;

  if(s_receive(socket, &enc_str) != 0){
    shutdown(socket, SHUT_RDWR);
    close(socket);
    return -2;
  }

  char** dec_str = message_decode(enc_str, NULL);
  char* alice_dh_pub_str = dec_str[0];
  BIGNUM *alice_dh_pub = BN_new();
  BN_hex2bn(&alice_dh_pub, alice_dh_pub_str);

  // generate y and g^y
  DH_generate_key(bob->dh);

  // calculate shared key
  bob = derive_key(bob, alice_dh_pub);

  BIGNUM *pub = BN_new();
  DH_get0_key(bob->dh, (const BIGNUM **)&pub, NULL);
  char *str_pub_key = BN_bn2hex(pub);

  // signing
  unsigned char* pub_keys = str_concat(str_pub_key, alice_dh_pub_str);
  int d_hash;
  unsigned char* hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys),&d_hash);

  unsigned char* sign_pub_keys = (char*) malloc(RSA_size(bob->rsa));
  unsigned int sign_len;
  RSA_sign(NID_sha1, hash_pub_keys, d_hash,
            sign_pub_keys, &sign_len, bob->rsa);

  // clean temp memory
  free(pub_keys);
  free(hash_pub_keys);

  // encryption with shared_key
  int e_k_len = 0;
  unsigned char* e_k = aes256_encrypt(bob->shared_key, bob->key_size,
    sign_pub_keys, sign_len, &e_k_len);

  free(sign_pub_keys);

  char *message[2];
  message[0] = str_pub_key;
  message[1] = byte_to_hex(e_k, e_k_len);
  char *encoded_str = message_encode(message, 2);

  // send g^y and E_k(S_b(SHA256(g^y,g^x))) to alice
  if(s_send(socket, encoded_str, strlen(encoded_str)) != 0){
    shutdown(socket, SHUT_RDWR);
    close(socket);
    return -2;
  }

  // get E_k(S_a(SHA256(g^x,g^y))) from alice
  free(enc_str);

  if(s_receive(socket, &enc_str) != 0){
    shutdown(socket, SHUT_RDWR);
    close(socket);
    return -2;
  }

  free(dec_str);
  dec_str = message_decode(enc_str, NULL);

  // verify E_k(S_b(SHA256(g^y,g^x)))
  e_k_len = 0;
  free(e_k);
  e_k = hex_to_byte(dec_str[0], &e_k_len);

  // decrypt
  sign_len = 0;
  sign_pub_keys = aes256_decrypt(bob->shared_key, bob->key_size,
    e_k, e_k_len, &sign_len);

  // verify sign
  pub_keys = str_concat(alice_dh_pub_str, str_pub_key);
  hash_pub_keys = get_hash_sha256(pub_keys, strlen(pub_keys),&d_hash);

  int verify = RSA_verify(NID_sha1, hash_pub_keys, d_hash,
    sign_pub_keys, sign_len, rsa_alice);
  if(verify != 1){
    write_log("Bob> Alice's signature error!!!");
    
    //close connection
    shutdown(socket, SHUT_RDWR);
    close(socket);
    
    write_log("Bob> Connection closed!");
    
    return -1; // Signature verification filure
  }

  write_log("Bob> Alice Trusted!");
  write_log("Bob> Ephemeral key created!");
  //Log SharedKey
  write_log_bytes("Bob EphemeralKey:", bob->shared_key, bob->key_size);

  return 0; // STS succeded
}
