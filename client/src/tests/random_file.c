#include <stdio.h>
#include <stdlib.h>
#include "jpeg_steg.h"


int main(int argc, char**argv){
  if((argc < 2) || (argc > 3)){
    fprintf(stderr, "Usage: %s directory [repeat]\n", argv[0]);
    exit(1);
  } else {
    int count = (argc == 2) ? 1 : atoi(argv[2]);
    for(int i  = 0; i < count; i++){
      char* path = random_file(argv[1]);
      fprintf(stderr, "path[%d] = %s\n", i, path);
    }
  }
  return 0;
}

