#include "onion.h"
#include "nep.h"
#include "defiantclient.h"
#include "onionlib.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>



int main(int argc, char** argv){
  if(argc != 3){
    fprintf(stderr, "Usage: %s <defiance private key path> <defiance public key path> <file path>\n", argv[0]);
    return 1;
  } else {
    /* we are going to make count many "signed >> captcha >> pow >> base" onions containing this nep */
    FILE *private_key_fp = fopen(argv[1], "r");
    FILE *public_key_fp = fopen(argv[2], "r");
    if(private_key_fp == NULL){
      fprintf(stderr, "Could not open private key file %s: %s\n",  argv[1], strerror(errno));
      return 1;
    } else if(public_key_fp == NULL){
      fprintf(stderr, "Could not open public key file %s: %s\n",  argv[2], strerror(errno));
      return 1;
    } else  { 
      int count = 0;
      int total = 12;
      char *nep = NULL;
      int errcode = defiant_lib_init(public_key_fp);
      char *path  = argv[3];
      srand(time(NULL));
      if(errcode != DEFIANT_OK){ 
        fprintf(stderr, "defiant_lib_init(): errcode = %d\n", errcode);
        return 1;
      } else {
        int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
        if(fd < 0){
          fprintf(stderr, "Couldn't open %s for writing\n", path);
          return 1;
        } else {
          errcode = get_nep(&nep, stderr, 1);
          if(errcode != DEFIANT_OK){
            fprintf(stderr, "Couldn't get nep: %d\n", errcode);
            return 1;
          }
          while(count < total){
            onion_t signed_onion = NULL;
            long int onion_id = -1;
            errcode = pack_nep(private_key_fp, public_key_fp, NULL, &onion_id, nep, &signed_onion, stderr, 1);
            if(errcode != DEFIANT_OK){  
              fprintf(stderr, "errcode = %d\n", errcode);
              return 1;
            }
            /* info_onion(stderr, signed_onion); */
            errcode = write_onion(fd, signed_onion);
            if(errcode != DEFIANT_OK){  
              fprintf(stderr, "errcode = %d\n", errcode);
              return 1;
            }
            free_onion(signed_onion);
            signed_onion = NULL;
            count++;
          }
          free(nep);
        }
        close(fd);
        defiant_lib_cleanup();
      }
      fclose(private_key_fp);
      fclose(public_key_fp);
    }
  }
  return 0;
}




