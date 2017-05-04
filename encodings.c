#include "encodings.h"

char *str_concat(char *s1, char *s2){
  int size1 = strlen(s1);
  int size2 = strlen(s2);
  char* res = (char*) malloc(sizeof(char) * size1 + size2 + 1);

  char* pt_r = res;

  char* pt_s = s1;
  for(int i = 0; i < size1; i++){
    *pt_r = *pt_s;
    pt_r++;
    pt_s++;
  }
  pt_s = s2;
  for(int i = 0; i < size2; i++){
    *pt_r = *pt_s;
    pt_r++;
    pt_s++;
  }
  *pt_r = '\0';

  return res;

}

char *str_append_char(char *s, char c){
  int size_res = strlen(s) + 1;
  char* res = (char*) malloc(sizeof(char) * size_res + 1);

  char* pt_r = res;

  char* pt_s = s;
  for(int i = 0; i < strlen(s); i++){
    *pt_r = *pt_s;
    pt_r++;
    pt_s++;
  }
  *pt_r = c;
  *(++pt_r) = '\0';

  return res;
}

char *message_encode(char **messages, int len){
  char *result = "";

  if(len > 1){
    int i = 1;
    result = str_concat(result, messages[0]);
    for (i = 1; i < len; i++){
      char *msg = messages[i];
      result = str_append_char(result, SEP);
      result = str_concat(result, msg);
    }
    result = str_concat(str_append_char("", SOP), str_append_char(result, EOP));
  } else if (len == 1) {
    result = str_concat(str_append_char("", SOP), str_append_char(messages[0], EOP));
  }
  return result;
}

char **message_decode(char *bytes){

}

void print_packet(char *bytes){
  unsigned char *byte = bytes;
  while(*byte != EOP){
    printf("%X", *byte);
    byte++;
  }
  printf("%X\n", *byte);
}
