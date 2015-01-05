#include <stdio.h>
#include <string.h>

#include "defiantclient.h"
#include "defiantrequest.h"

#include "defiant_params.h"



int main(int argc, char** argv){
  if((argc < 2) || (argc > 3)){
    fprintf(stderr, "Usage: %s <server url> [port]\n", argv[0]);
  } else {
    char password[DEFIANT_REQ_REP_PASSWORD_LENGTH + 1];
    char* server = argv[1];
    int secure = (argc == 3) && !strcmp(argv[2], "443");
    char* url = NULL;
    bf_params_t *params =  NULL;
    
    int errcode = bf_char64_to_params(defiant_params_P, defiant_params_Ppub, &params);
    
    if(errcode != DEFIANT_OK){ 
      fprintf(stderr, "Couldn't load hardwired params, errcode = %d, go figure... \n", errcode);
      exit(0);
    }
    
    /* generate a random password */
    srand(time(NULL));
    randomPasswordEx(password, DEFIANT_REQ_REP_PASSWORD_LENGTH + 1, 0);
    if(secure){
      errcode = generate_defiant_ssl_request_url(params, password, server, "probably/not/a/valid/path/to/picture.png", &url);
    } else {
      errcode = generate_defiant_request_url(params, password, server, "probably/not/a/valid/path/to/picture.png", &url);
    }
    
    if(errcode == DEFIANT_OK){
      fprintf(stdout, "%s\n%s\n", password, url);
      free(url);
    }
    bf_free_params(params);
    params = NULL;
  }
  return 0;
}

