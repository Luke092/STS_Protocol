#ifndef H_ENCODINGS
#define H_ENCODINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define SOP 0xFF
#define EOP 0xFE
#define SEP 0xAA

/*
*  Packet format:
*
* | SOP | LEN1 |  DATA 1  | SEP | LEN 2  |  DATA 2  | ... | EOP |
* |  1  |  2   |          |  1  |   2    |          | ... |  1  |
*
*/

// encode an array of messages
char *message_encode(char **messages, int len);
// decode a message to an array of strings
char **message_decode(char *bytes);

void print_packet(char *bytes);

#endif
