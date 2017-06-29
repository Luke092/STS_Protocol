#ifndef H_CLIENT
#define H_CLIENT

#include "net.h"

// connect to remote server
int s_connect(char* addr, int port);

/* 
 * write a message in a stream socket
 * @return: 0 on success error code instead
 *	- (-1) write error
 *	- (-2) socket shutted down
 *
 * @sockfd: socket file
 * @message: message to send via socket
 * @len: message length
 */
int s_send(int sockfd, char* message, int len);

/* 
 * read a message from a stream socket
 * @return: 0 on success error code instead
 *	- (-1) read error
 *	- (-2) socket shutted down
 *
 * @sockfd: socket file
 * @message: pointer in witch the message will be placed
 */
int s_receive(int sockfd, char **message);

#endif
