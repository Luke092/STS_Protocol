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
* | SOP |  DATA 1  | SEP |  DATA 2  | SEP | ... | EOP |
* |  1  |          |  1  |          |  1  | ... |  1  |
*
*/

// encode an array of messages
char *message_encode(char **messages, int len);
// decode a message to an array of strings
char **message_decode(char *bytes, int *res_le);

// relocate the array in a new memory position with a new size
char** reallocate(char **matrix, int len_i, int len_f);
// append a string into an array
char** matrix_append(char **matrix, int len, char *str);

// convert byte array to hex string
char* byte_to_hex(unsigned char* bytes, int len);
// convert hex string to byte array
unsigned char* hex_to_byte(char* hex_str, int *len);

char *str_concat(char *s1, char *s2);
void print_bytes(unsigned char* bytes, int len);

#endif
