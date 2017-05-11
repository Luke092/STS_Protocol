#include "server.h"

int createSocket(int port){
  int sockfd;

  struct sockaddr_in srv_addr;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0){
    return -1; // socket cannot be created
  }
  bzero((char *) &srv_addr, sizeof(srv_addr));
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = INADDR_ANY;
  srv_addr.sin_port = htons(port);
  if(bind(sockfd, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) < 0){
    return -2; // socket cannot be binded
  }

  return sockfd;
}

void listenLoop(int sockfd, CB_handle_client cb){
  int newsockfd, clilen;

  struct sockaddr_in cli_addr;

  listen(sockfd, 5);
  clilen = sizeof(cli_addr);

  while(1){
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0){
      printf("ERROR on accept\n");
    } else {
      // generate new process for communication handling
      int pid = fork();
      if(pid == 0){
        cb(newsockfd);
      }
    }
  }

  //Close socket
  close(sockfd);
}
