#include "logging.h"

int isDebugMode = 0;
FILE *debugFile = NULL;

void set_debug(int enable, FILE *f){
  isDebugMode = enable;
  debugFile = f;
}

void change_mode(int enable){
	isDebugMode = enable;
}

void write_log(char* message){
	if(isDebugMode){
		fprintf(stderr, "%s\n", message);
	}
}