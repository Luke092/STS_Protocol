#ifndef H_CLIENT
#define H_CLIENT

#include "net.h"
#include <stdio.h>
#include <string.h>

int s_connect(char* addr, int port);
int s_send(int sockfd, char* message, int len);
int s_receive(int sockfd, char* message, int* len);

#endif
