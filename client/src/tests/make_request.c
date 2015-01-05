#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "defiantclient.h"
#include "defiantrequest.h"

#include "defiant_params.h"
#include "platform.h"

int main(int argc, char** argv){
  char password_in[DEFIANT_REQ_REP_PASSWORD_LENGTH + 1];
  int errcode;
  char* url = NULL;
  char* password_out = NULL;
  bf_params_t *params =  NULL;

  errcode = bf_char64_to_params(defiant_params_P, defiant_params_Ppub, &params);

  if(errcode != DEFIANT_OK){ 
    fprintf(stderr, "Couldn't load hardwired params, errcode = %d, go figure... \n", errcode);
    exit(0);
  }

  /* generate a random password */
  srand(time(NULL));
  randomPasswordEx(password_in, DEFIANT_REQ_REP_PASSWORD_LENGTH + 1, 0);
  fprintf(stdout, "password_in = %s of length %" PRIsizet "\n", password_in, strlen(password_in));

  errcode = generate_defiant_request_url(params, password_in, "vm06.csl.sri.com", "probably/not/a/valid/path/to/picture.png", &url);

  bf_free_params(params);
  params = NULL;



  if(errcode == DEFIANT_OK){
    char *keyfile = "../../data/vm06_private_key.bin";
    bf_key_pair_t* key_pair = NULL;
    FILE *fp = fopen(keyfile, "rb");
    if(fp == NULL){
      fprintf(stderr, "Couldn't open key-pair file, %s, go figure... \n", strerror(errno));
      exit(0);
    }
    errcode = bf_read_key_pair(fp, &key_pair);
    if(errcode != DEFIANT_OK){
      fprintf(stderr, "Couldn't load key pair from %s, errcode = %d, go figure... \n", keyfile, errcode);
      exit(0);
    }
    fprintf(stdout, "url = %s\n", url);
    errcode = is_defiant_request(key_pair, url, &password_out);
    if(errcode == DEFIANT_OK){
      fprintf(stdout, "password_out = %s of length %" PRIsizet "\n", password_out, strlen(password_out));
    } else {
      fprintf(stdout, "is_defiant_request errcode = %d\n", errcode);
    }
    fclose(fp);
    bf_free_key_pair(key_pair);
    key_pair = NULL;
  } else {
    fprintf(stdout, "generate_defiant_request_url errcode = %d\n", errcode);
  }
  //fprintf(stdout, "%s %s\n", url, password_out);
  
  free(url);
  free(password_out);

  return 0;
}

