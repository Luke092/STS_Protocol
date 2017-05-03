#ifndef H_CLIENT
#define H_CLIENT

#include "net.h"
#include <stdio.h>
#include <string.h>

// connect to remote server
int s_connect(char* addr, int port);

// write a message in a stream socket
int s_send(int sockfd, char* message, int len);

// read a message from a stream socket
int s_receive(int sockfd, char* message, int* len);

#endif
