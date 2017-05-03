#include "client.h"

int s_connect(char* addr, int port){
  int sockfd;

  struct sockaddr_in serv_addr;
  struct hostent *server;

  char buffer[256];

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return -1; // cannot create socket
  /*server = gethostbyname("localhost");
  if (server == NULL) {
      return -2; // cannot find the host
  }*/
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(addr);
  /*bcopy((char *)server->h_addr,
       (char *)&serv_addr.sin_addr.s_addr,
       server->h_length);*/
  serv_addr.sin_port = htons(port);
  if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
    return -3; // cannot connect to the server

return sockfd;
}

int s_send(int sockfd, char* message, int len){
  int n;
  n = write(sockfd, message, len);
  if (n < 0){
    printf("ERROR writing to socket\n");
    return -1;
   }
   return 0;
}

int s_receive(int sockfd, char* message, int* len){
  int n;
  char buffer[256];
  bzero(buffer,256);
  n = read(sockfd,buffer,255);
  if (n < 0){
    printf("ERROR reading from socket");
    return -1;
  }

  *len = n;
  strcpy(message, buffer);

  return 0;
}
