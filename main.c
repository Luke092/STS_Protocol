#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "crypto.h"

#define MILLS(X) (X * 1000)
#define SEC(X) (MILLS(X) * 1000)

#define PORT 1055

void server_fun();
void client_fun();
void handleMessage(int socket, char *message, int len);

int main(){
  /*int pid = fork();

  if(pid == 0){
    usleep(SEC(1));
    client_fun();
  } else {
    server_fun();
  }*/

  DH *dh = get_params("param.pem", 1024);
  DHparams_print_fp(stdout, dh);

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

void handleMessage(int socket, char *message, int len){
  printf("Message Handling -> \t len = %d \t mex: %s\n", len, message);
  char echo[len + 2];
  strcpy(echo, message);
  echo[len - 2] = '\n';
  echo[len - 1] = '\0';
  s_send(socket, echo, len + 2);
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
      s_send(sockfd, "Hello!", strlen("Hello"));
      usleep(SEC(5));
    }
  }
}
