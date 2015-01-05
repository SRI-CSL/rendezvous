#include "onion.h"
#include "onionlib.h"
#include "nep.h"
#include "defiantclient.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char** argv){
  if(argc != 4){
    fprintf(stderr, "Usage: %s <defiance public key path>  <defiance public key path> <count>\n", argv[0]);
    return 1;
  } else {
    FILE *private_key_fp = fopen(argv[1], "r");
    FILE *public_key_fp = fopen(argv[2], "r");

    if(private_key_fp == NULL){
      fprintf(stderr, "Could not open private key file %s: %s\n",  argv[1], strerror(errno));
      return 1;
    } if(public_key_fp == NULL){
      fprintf(stderr, "Could not open public key file %s: %s\n",  argv[2], strerror(errno));
      return 1;
    } else {
      int nepc = atoi(argv[3]);
      int errcode;
      if(nepc > 0){
        int i;
        char** nepv = (char**)calloc(nepc, sizeof(char*));
        long int* onion_ids = (long int*)calloc(nepc, sizeof(long int));
        
        for(i = 0; i < nepc; i++){
          char *nep = NULL;
          errcode = get_nep(&nep, stderr, 1);
          if(errcode != DEFIANT_OK){
            fprintf(stderr, "Getting nep failed: %d\n", errcode);
            return 1;
          }
          nepv[i] = nep;
        }
        onion_t signed_collection = NULL;
        
        errcode = defiant_lib_init(public_key_fp);
        
        srand(time(NULL));
        
        errcode = pack_neps(private_key_fp, public_key_fp, NULL, onion_ids, nepc, nepv, &signed_collection, stderr, 1);
        
        free(signed_collection);
        
        for(i = 0; i < nepc; i++){ free(nepv[i]); }
        free(nepv);
        
        defiant_lib_cleanup();
        return 0;
      }
      fclose(public_key_fp);
    }
  }
  return 1;
}





