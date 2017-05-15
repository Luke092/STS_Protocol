#include "client.h"

int s_connect(char* addr, int port){
  int sockfd;

  struct sockaddr_in serv_addr;
  struct hostent *server;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return -1; // cannot create socket
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(addr);
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

char* s_receive(int sockfd){
  int n;
  char buffer[1024];
  bzero(buffer,1024);

  do{
    n = read(sockfd, buffer, 1023);
  }while (n == 0);
  if (n < 0){
    printf("ERROR reading from socket\n");
    return NULL;
  }

  int m_len = strlen(buffer);
  char *message = (char *) malloc(sizeof(char) * m_len + 1);
  bzero(message, m_len + 1);
  bcopy(buffer, message, m_len);
  return message;
}
