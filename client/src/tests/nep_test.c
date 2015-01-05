#include <stdio.h>
#include "nep.h"
#include "defianterrors.h"



int main(int argc, char**argv){
  char* nep = NULL;
  int retcode = get_nep(&nep, stderr, 1);
  if(retcode == DEFIANT_OK){
    fprintf(stdout, "%s\n", nep);
  } else {
    fprintf(stderr, "get_nep failed: %d\n", retcode);
  }
  return 0;
}

