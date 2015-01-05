#include "onion.h"
#include "defiantclient.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>



int main(int argc, char** argv){
  int status = 1;
  if(argc != 4){
    fprintf(stderr, "Usage: %s <defiant public key path> <onion file path> <password>\n", argv[0]);
  } else {
    FILE *public_key_fp = fopen(argv[1], "r");
    
    if(public_key_fp == NULL){
      fprintf(stderr, "Could not open public key file %s: %s\n",  argv[1], strerror(errno));
      exit(EXIT_FAILURE);
    } else {
      char *path  = argv[2];
      char *password = (argc == 4) ? argv[3] : DEFIANT_TEST_PASSWORD;
      int errcode = defiant_lib_init(public_key_fp);
      if(errcode != DEFIANT_OK){ 
        fprintf(stderr, "defiant_lib_init(): errcode = %d\n", errcode);
      } else {
        char* encrypted_onion = NULL;
        int encrypted_onion_size = 0;
        errcode = file2bytes(path, &encrypted_onion_size, &encrypted_onion);
        if(errcode != DEFIANT_OK){
          fprintf(stderr, "Reading data from %s failed\n", path);
        } else {
          onion_t onion = NULL;
          int onion_sz = 0;
        
          onion = (onion_t)defiant_pwd_decrypt(password, (const uchar*)encrypted_onion, encrypted_onion_size, &onion_sz);
          if (onion == NULL) {
            fprintf(stderr, "Decrypting onion failed: No onion\n");
          } else if (onion_sz < (int)sizeof(onion_header_t)) {
            fprintf(stderr, "Decrypting onion failed: onion_sz less than onion header");
          } else if (!ONION_IS_ONION(onion)) {
            fprintf(stderr, "Decrypting onion failed: Invalid magic\n");
          } else if (onion_sz != ONION_SIZE(onion)) {
            fprintf(stderr, "Decrypting onion failed: Wrong size\n");
          } else {
            errcode = verify_onion(public_key_fp, onion);
            if(errcode == DEFIANT_OK){
              fprintf(stderr, "onion VERIFIED\n");            
              status = 0;
            } else {
              fprintf(stderr, "onion BOGUS\n");
            }
            info_onion(stderr, onion);
            free_onion(onion);
            onion = NULL;
          }
          free(encrypted_onion);
        }
      }
      defiant_lib_cleanup();
      return status;
    }
  }
}



