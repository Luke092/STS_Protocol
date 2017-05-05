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

char** reallocate(char **matrix, int len_i, int len_f){
  char **res = (char*) malloc(sizeof(char*) * len_f);
  char **r_ptr = res;
  char **s_ptr = matrix;
  int i;
  for(i = 0; i < len_i; i++){
    *r_ptr = *s_ptr;
    r_ptr++;
    s_ptr++;
  }
  free(matrix);
  return res;
}

char** matrix_append(char **matrix, int len, char *str){
  char **res;
  res = reallocate(matrix, len, len + 1);
  res[len] = str;
  return res;
}

char **message_decode(char *bytes, int *res_len){
  char **result = NULL;
  int r_len = 0;
  unsigned char *ptr_byte = bytes;
  if(*ptr_byte != SOP){
    *res_len = -1;
    return NULL;
  } else {
    do{
      ptr_byte++;
      int len_msg = 0;
      unsigned char *count_ptr = ptr_byte;
      while(*count_ptr != SEP && *count_ptr != EOP){
        len_msg++;
        count_ptr++;
      }
      int i;
      char *msg = (char *)malloc(sizeof(char) * len_msg + 1);
      char *msg_ptr = msg;
      for(i = 0; i < len_msg; i++){
        *msg_ptr = *ptr_byte;
        msg_ptr++;
        ptr_byte++;
      }
      msg_ptr = '\0';
      result = matrix_append(result, r_len, msg);
      r_len++;
    } while (*ptr_byte != EOP);
  }
  *res_len = r_len;
  return result;
}

void print_packet(char *bytes){
  unsigned char *byte = bytes;
  while(*byte != EOP){
    printf("%X", *byte);
    byte++;
  }
  printf("%X\n", *byte);
}
