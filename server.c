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

void listenLoop(int sockfd, CB_handle_message cb){
  int newsockfd, clilen;
  int cID = 0;

  struct sockaddr_in cli_addr;

  listen(sockfd, 5);
  clilen = sizeof(cli_addr);
  //TODO: implement infinit loop
  while(1){
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0){
      printf("ERROR on accept\n");
    } else {
      cID++;
      int pid = fork();
      if(pid == 0){
        manageConnection(cID, newsockfd, cb);
      }
    }
  }

  //Close socket
  close(sockfd);
}

void manageConnection(int id, int newsockfd, CB_handle_message cb){
  char buffer[256];
  int n;
  // define blocking mode on read
  int iMode = 0;
  ioctl(newsockfd, FIONBIO, &iMode);

  while(1){
    bzero(buffer,256);
    do{
      n = read(newsockfd, buffer, 255);
    }while (n == 0); // repeat the read if i read 0 bytes

    printf("ChildHandler %d\t", id);
    // callback call
    int len = strlen(buffer);
    char message[len + 1];
    bzero(message, len+1);
    bcopy(buffer, message, len);
    cb(newsockfd, message, len);
  }

  close(newsockfd);
}
