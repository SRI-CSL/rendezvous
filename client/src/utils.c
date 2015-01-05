#include <string.h>
#include "utils.h"

char* duplicate(const char* value){
  if(value != NULL){
    char * retval = (char *)calloc(strlen(value) + 1, sizeof(char));
    if(retval != NULL){
      strcpy(retval, value);
      return retval;
    }
  }
  return NULL;
}



size_t callback(void *contents, size_t size, size_t nmemb, void *userp){
  size_t realsize = size * nmemb;
  response *resp = (response *)userp;
  resp->buffer = realloc(resp->buffer, resp->buffer_size + realsize + 1);
  if (resp->buffer != NULL) {
    memcpy(&(resp->buffer[resp->buffer_size]), contents, realsize);
    resp->buffer_size += realsize;
    resp->buffer[resp->buffer_size] = 0;
  }
  return realsize;
}
 
