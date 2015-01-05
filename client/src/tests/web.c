#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defiantclient.h" 
#include "cweb.h" 

char *url = "http://tinyurl.com/ianamason";



int main(int argc, char** argv){
  if(argc != 2){ 
    fprintf(stderr, "Usage: %s url\n", argv[0]);
    /* return 0; */
  } else {
    url = argv[1];
  }
  {
    long httpCode;
    char* redirectURL = NULL;
    int retcode = getRedirect(url, &httpCode, &redirectURL);
    if(retcode){
      fprintf(stderr, "%ld %s\n", httpCode, redirectURL);
    } else {
      fprintf(stderr, "getRedirect failed (%ld)\n", httpCode);
    }
  }
  return 0;
}

