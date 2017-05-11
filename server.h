#ifndef H_SERVER
#define H_SERVER

#include "net.h"
#include "client.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <strings.h>

// callback definition for handling message from clients
typedef void (*CB_handle_message)(int cli_socket);

// create new socket
int createSocket(int port);
// start listening on a socket
void listenLoop(int sockfd, CB_handle_message cb);
// manage single client comminications
void manageConnection(int id, int newsockfd, CB_handle_message cb);

#endif
