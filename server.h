#ifndef H_SERVER
#define H_SERVER

#include "net.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <strings.h>

typedef void (*CB_handle_message)(int socket, char *message, int len);

int createSocket(int port);
void listenLoop(int sockfd, CB_handle_message cb);
void manageConnection(int id, int newsockfd, CB_handle_message cb);

#endif
