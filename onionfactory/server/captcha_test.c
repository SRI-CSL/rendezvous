#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defianterrors.h"
#include "onion.h"


int main(int argc, char** argv){
  if(argc != 3){
    fprintf(stderr, "Usage: %s password file\n", argv[0]);
  } else {
    int errcode = makeCaptcha(argv[1], argv[2]);
    if(errcode != DEFIANT_OK){
      fprintf(stderr, "makeCaptcha returned %d\n", errcode);
      if((errcode == DEFIANT_MISCONFIGURED) && (getenv("DEFIANT_CLASSPATH") == NULL)){
        fprintf(stderr, "Looks like the environment variable DEFIANT_CLASSPATH is NOT set.");
      }
    }
  }
  return 0;
}
