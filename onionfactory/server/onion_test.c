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

#define PEEL   0

void writeAndReadOnion(char *path, onion_t *onionp){
  if(onionp == NULL){ 
    fprintf(stderr, "Bad onion\n");
  } else {
    int errcode = onion2file(path, *onionp);
    info_onion(stderr, *onionp);
    if(errcode != DEFIANT_OK){  
      fprintf(stderr, "Writing to %s failed with %d", path, errcode);
    } else {
      free_onion(*onionp);
      *onionp = NULL;
      errcode = file2onion(path, onionp);
      if(errcode == DEFIANT_OK){
        fprintf(stderr, "file2onion: %d\n", errcode);
        info_onion(stderr, *onionp);
      }
    }
  }
}

void peel(onion_t onion){
  onion_t inner = NULL;
  int errcode;

  fprintf(stderr, "Peeling ...\n");
      
  errcode = peel_pow_onion(onion, &inner);
  
  if(errcode == DEFIANT_OK){
    fprintf(stderr, "Peeling SUCCESS:\n");
    info_onion(stderr, inner);
    free(inner);
  } else {
    fprintf(stderr, "Peeling failed :-(\n");
    return;
  }
  
  
}



int main(int argc, char** argv){
  
  if(argc != 3){
    fprintf(stderr, "Usage: %s <defiance private key path> <defiance public key path>\n", argv[0]);
    return 1;
  } else {
    FILE *public_key_fp = fopen(argv[1], "r");
    FILE *private_key_fp = fopen(argv[2], "r");
    
    if(private_key_fp == NULL){
      fprintf(stderr, "Could not open private key file %s: %s!\n",  argv[1], strerror(errno));
      return 1;
    } else if(public_key_fp == NULL){
      fprintf(stderr, "Could not open public key file %s: %s\n",  argv[2], strerror(errno));
      return 1;
    } else /* public_key_fp OK */ {
      int errcode = defiant_lib_init(public_key_fp);
      if(errcode != DEFIANT_OK){ 
        fprintf(stderr, "defiant_lib_init(): errcode = %d\n", errcode);
        return 1;
      } else /* defiant_lib_init OK */ { 
        int count = 10;
        char *nep = NULL;
        
        onion_t base_onion     = NULL;
        onion_t pow_onion      = NULL;
        onion_t captcha_onion  = NULL;
        onion_t signed_onion   = NULL;
        errcode = get_nep(&nep, stderr, 1);
        if(errcode != DEFIANT_OK){ 
          fprintf(stderr, "get_nep: errcode = %d\n", errcode);
          return 1;
        } else {
          size_t dsz = strlen(nep) + 1; /* keep the nep NULL-terminated */
          
          errcode = make_onion(BASE, 0, dsz, NULL, (void *)nep, &base_onion);
          fprintf(stderr, "errcode = %d\n", errcode);
          if(errcode != DEFIANT_OK){  return 1; }
          
          writeAndReadOnion("base_onion.bin", &base_onion);
          
          if(base_onion != NULL){
            size_t osz = sizeof(onion_header_t) + ONION_PUZZLE_SIZE(base_onion) + ONION_DATA_SIZE(base_onion);
            fprintf(stderr, "base onion size: %zd\n", osz);
            /* now lets wrap the base onion into a pow onion */
            errcode = make_onion(POW, 0, osz, NULL, (void *)base_onion, &pow_onion);
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            info_onion(stderr, pow_onion);
            writeAndReadOnion("pow_onion.bin", &pow_onion);
            
            if(PEEL){ peel(pow_onion);  }
            
            errcode = make_captcha_onion(ONION_SIZE(pow_onion), (void *)pow_onion, &captcha_onion); 
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            
            info_onion(stderr, captcha_onion);
            
            free_onion(pow_onion);
            pow_onion = NULL;
            
            free_onion(captcha_onion);
            captcha_onion = NULL;
          }
      
          srand(time(NULL));
          
          while(1 && (count > 0)){
            char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
            char cpassword[DEFIANT_CAPTCHA_PASSWORD_LENGTH];
            randomPasswordEx(cpassword, DEFIANT_CAPTCHA_PASSWORD_LENGTH, 0);
            randomPassword(password, DEFIANT_CLIENT_PASSWORD_LENGTH);
            password[0] =  password[1]  = 'a';
            fprintf(stderr, "password = %s\n", password);
            fprintf(stderr, "[%s]\n", cpassword); 
            errcode = make_pow_onion_aux(password, ONION_SIZE(base_onion), (void *)base_onion, &pow_onion);
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            errcode = check_pow_onion(password, pow_onion, base_onion);
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            errcode = make_captcha_onion_aux(password, ONION_SIZE(pow_onion), (void *)pow_onion, &captcha_onion);
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            errcode = check_captcha_onion(password, captcha_onion, pow_onion);
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            errcode = make_signed_onion(private_key_fp, ONION_SIZE(captcha_onion), (void *)captcha_onion, &signed_onion); 
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            errcode = check_signed_onion(public_key_fp, signed_onion, captcha_onion);
            fprintf(stderr, "errcode = %d\n", errcode);
            if(errcode != DEFIANT_OK){  return 1; }
            info_onion(stderr, signed_onion);
            
            
            if(PEEL){ peel(pow_onion); }
            
            free_onion(pow_onion);
            pow_onion = NULL;
            free_onion(captcha_onion);
            captcha_onion = NULL;
            free_onion(signed_onion);
            signed_onion = NULL;
            count--;
          }
          
          free(nep);
          
          free_onion(base_onion);
          free_onion(pow_onion);
          
        }
        defiant_lib_cleanup();
      }
      fclose(public_key_fp);
    }
  }
  return 0;
}


