#ifndef H_LOG
#define H_LOG

#include <stdio.h>

void set_debug(int enable, FILE *f);
void change_mode(int enable);
void write_log(char* message);
void write_log_bytes(char* message, unsigned char* bytes, int len);

#endif