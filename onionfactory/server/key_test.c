#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "defiantclient.h"
#include "defiantserver.h"


static void sign_test(char data[], FILE* private_key_fp, FILE* public_key_fp){
  uchar *signature = NULL;
  unsigned int signature_sz = 0;
  int data_size = strlen(data) + 1;
  int retcode = defiant_sign(private_key_fp, data, data_size, &signature, &signature_sz);
  if(retcode != DEFIANT_OK){
    fprintf(stderr, "defiant_sign returned %d\n", retcode);
    return;
  } else {
    fprint64(stderr, signature, signature_sz);
    retcode = defiant_verify(public_key_fp, data, data_size, signature, signature_sz);
    if(retcode  != DEFIANT_OK){
      fprintf(stderr, "defiant_verify returned %d\n", retcode);
      return;
    } else {
      fprint64(stderr, signature, signature_sz);
    }
  }
  free(signature);
  signature = NULL;
  defiant_lib_cleanup();
  fprintf(stderr, "So far so good...\n");
}

// ./key_test ../../client/data/defiant_private.pem ../../client/data/defiant_public.pem

int main(int argc, char** argv){
  char data[] = "This is something that may or may not be worth signing, but I'm going to sign it anyway, so there!";
  if(argc != 3){
    fprintf(stderr, "Hint: next time try something like: %s %s!\n",  argv[0], "../../client/data/defiant_private.pem ../../client/data/defiant_public.pem");
    sign_test(data, NULL, NULL);
  } else {
    FILE *private_key_fp, *public_key_fp;
    
    private_key_fp = fopen(argv[1], "r");
    
    if(private_key_fp == NULL){
      fprintf(stderr, "Could not open private key file %s: %s!\n",  argv[1], strerror(errno));
      exit(EXIT_FAILURE);
    }
    
    public_key_fp = fopen(argv[2], "r");
    
    if(public_key_fp == NULL){
      fprintf(stderr, "Could not open public key file %s: %s\n",  argv[2], strerror(errno));
      exit(EXIT_FAILURE);
    }
    
    sign_test(data, private_key_fp, public_key_fp);
  }
  return 0;
}
