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
		fprintf(debugFile, "%s\n", message);
	}
}

void write_log_bytes(char* message, unsigned char* bytes, int len){
	if(isDebugMode){
		fprintf(debugFile, "%s", message);
		int i;
		for(i = 0; i < len - 1; i++){
			fprintf(debugFile, "%.2X-", bytes[i]);
		}
		fprintf(debugFile, "%.2X", bytes[len - 1]);
		fprintf(debugFile, "\n");
	}
}