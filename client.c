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
    write_log("ERROR writing to socket\n");
    return -1;
  } else if(n == 0){
    write_log("Socket shutted down\n");
    return -2;
  }
   return 0;
}

int s_receive(int sockfd, char **message){
  int n;
  char buffer[1024];
  bzero(buffer,1024);

  n = read(sockfd, buffer, 1023);
  if (n < 0){
    // socket error
    printf("ERROR reading from socket: %s\n", strerror(errno));
    return -1;
  } else if(n == 0){
    // socket shutdown
    write_log("Socket shutted down\n");
    return -2;
  }

  int m_len = strlen(buffer);
  char *tmp = (char *) malloc(sizeof(char) * m_len + 1);
  bzero(tmp, m_len + 1);
  bcopy(buffer, tmp, m_len);
  *message = tmp;
  return 0;
}
