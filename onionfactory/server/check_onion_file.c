#include "onion.h"
#include "onionlib.h"
#include "defiantclient.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>



int main(int argc, char** argv){
  if(argc != 3){
    fprintf(stderr, "Usage: %s <defiance public key path> <file path>\n", argv[0]);
    return 1;
  } else {
    char *path  = argv[2];
    FILE *public_key_fp = fopen(argv[1], "r");

    if(public_key_fp == NULL){
      fprintf(stderr, "Could not open public key file %s: %s\n",  argv[1], strerror(errno));
      return 1;
    } else {
      int errcode = defiant_lib_init(public_key_fp);
      if(errcode != DEFIANT_OK){ 
        fprintf(stderr, "defiant_lib_init(): errcode = %d\n", errcode);
        return 1;
      } else {
        int fd = open(path, O_RDONLY, S_IRWXU);
        if(fd < 0){
          fprintf(stderr, "Couldn't open %s for reading\n", path);
          return 1;
        } else {
          onion_t onion;
          int count = 0;
          while((errcode = read_onion(fd, &onion)) == DEFIANT_OK){
            count++;
            errcode = verify_onion(public_key_fp, onion);
            fprintf(stderr, "onion %d: %s\n", count, errcode == DEFIANT_OK ? "VERIFIED" : "BOGUS");
            info_onion(stderr, onion);
            free_onion(onion);
            onion = NULL;
          }
          fprintf(stderr, "looked at %d onions\n", count);
        }
        close(fd);
        defiant_lib_cleanup();
      }
      fclose(public_key_fp);
    }
  }
  return 0;
}



