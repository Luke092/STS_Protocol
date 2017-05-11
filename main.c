#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "crypto.h"
#include "encodings.h"

#define MILLS(X) (X * 1000)
#define SEC(X) (MILLS(X) * 1000)

#define PORT 1056

void server_fun();
void client_fun();
void handleMessage(int cli_socket);

int main(){
  int pid = fork();

  if(pid == 0){
    usleep(SEC(1));
    client_fun();
  } else {
    server_fun();
  }

  /*DH *dh = get_params("./params/dh_param.pem", 1024);
  DHparams_print_fp(stdout, dh);
  gen_keypair(dh);
  BIGNUM *p = BN_new();
  BIGNUM *g = BN_new();
  DH_get0_pqg(dh, &p, NULL, &g);
  char *msgs[2];
  msgs[0] = BN_bn2hex(p);
  msgs[1] = BN_bn2hex(g);
  char *pkg = message_encode(msgs, 2);
  print_packet(pkg);
  int r_len = 0;
  char **decode = message_decode(pkg, &r_len);
  printf("r_len = %d\n", r_len);
  for(int i = 0; i < r_len; i++){
    printf("S%d: %s\n", i+1, decode[i]);
  }*/

  //RSA *rsa = read_rsa_key("./alice/pub.pem", NULL);

  return 0;
}

void server_fun(){
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
    listenLoop(sockfd, handleMessage);
  }
}

void handleMessage(int cli_socket){
  while(1){
    char *message;
    int len;
    message = s_receive(cli_socket);
    len = strlen(message);
    printf("Message Handling -> \t len = %d \t mex: %s\n", len, message);
    char echo[len + 2];
    strcpy(echo, message);
    echo[len] = '\n';
    echo[len + 1] = '\0';
    s_send(cli_socket, echo, len + 2);
  }
}

void client_fun(){
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
    while(1){
      char *buf = "Ciao Mondo!";
      s_send(sockfd, buf, strlen(buf));
      char *reply;
      reply = s_receive(sockfd);
      printf("Server> %s", reply);
      usleep(SEC(5));
    }

  }
}
