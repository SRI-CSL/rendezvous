#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <unistd.h>
#include <errno.h>

#include "../defiantclient.h"
#include "../defiantrequest.h"
#include "../defiant_params.h"
#include "../defianterrors.h"
#include "../utils.h"
#include "../onion.h"
#include "../jpeg_steg.h"

static const int ignore_certificates = 1;

static int make_request(char *server, int port, char** passwordp, char** urlp);

int process_reply(FILE* public_key_fp, char* password, char* reply, size_t reply_size, int reply_type);

static int parseargs(int argc, char** argv, char** public_key_path, char** server, int* port, char** proxyserver, int* proxyport, int* proxytype);
static int parseproxyaddress(const char *proxyaddr, char **proxyserver, int *proxyport);


int main(int argc, char** argv){
  if((argc < 3) || (argc > 6)){
    fprintf(stderr, "Usage: %s <defiance public key> <server> [port  [<sockshost:socksport> <proxytype (libcur integer code)>]\n", argv[0]);
  } else {
    char *public_key_path = NULL, *server = NULL, *proxyserver = NULL, *url = NULL, *password = NULL, *reply = NULL;
    int port = 0, proxyport = 0, proxytype = 0, reply_type = 0;
    size_t reply_size = 0;

    int  errcode = parseargs(argc, argv, &public_key_path, &server, &port, &proxyserver, &proxyport, &proxytype);


    if(errcode == DEFIANT_OK){

      FILE *public_key_fp;
    
      public_key_fp = fopen(public_key_path, "r");
    
      if(public_key_fp == NULL){
        fprintf(stderr, "Could not open public key file %s: %s\n",  public_key_path, strerror(errno));
        goto clean_up;
      }

      errcode = make_request(server, port, &password, &url);
      
      if(errcode == DEFIANT_OK){
        int mode = (port == 443) && ignore_certificates;
        fprintf(stderr, 
                "server=%s\nport=%d\nproxyserver=%s\nproxyport=%d\nproxytype=%d\npassword=%s\nurl=%s\n", 
                server, port, proxyserver, proxyport, proxytype, password, url);
        
        errcode = send_request(url, mode, proxyserver, proxyport, proxytype, &reply, &reply_size, &reply_type);
        
        if(errcode == DEFIANT_OK){
          
          errcode =  process_reply(public_key_fp, password, reply, reply_size, reply_type);


          if(errcode == DEFIANT_OK){
            fprintf(stderr, "Happy happy joy joy\n");
          } else {
            fprintf(stderr, "process_reply failed: %s\n", defiant_strerror(errcode));
          }
        } else {
          fprintf(stderr, "send_request failed: %s\n", defiant_strerror(errcode));
        }
      } else {
        fprintf(stderr, "make_request failed: %s\n", defiant_strerror(errcode));
      }
    } else {
      fprintf(stderr, "parseargs failed: %s\n", defiant_strerror(errcode));
    }


    
  clean_up:
    
    free(proxyserver);
    free(url);
    free(password);
    free(reply);
  }
}

int make_request(char *server, int port, char** passwordp, char** urlp){
  int retcode = DEFIANT_DATA;
  if((server == NULL) || (passwordp == NULL) || (urlp == NULL)){
    return retcode;
  } else {
    char* url = NULL;
    char password[DEFIANT_REQ_REP_PASSWORD_LENGTH + 1];
    int secure = (port == 443);
    bf_params_t *params =  NULL;
    int errcode = bf_char64_to_params(defiant_params_P, defiant_params_Ppub, &params);
    if(errcode != DEFIANT_OK){ 
      fprintf(stderr, "Couldn't load hardwired params, errcode = %d, go figure... \n", errcode);
      return DEFIANT_CRYPTO;
    }
    /* generate a random password */
    srand(time(NULL) + getpid());
    randomPasswordEx(password, DEFIANT_REQ_REP_PASSWORD_LENGTH + 1, 0);
    if(secure){
      errcode = generate_defiant_ssl_request_url(params, password, server, "probably/not/a/valid/path/to/picture.png", &url);
    } else {
      errcode = generate_defiant_request_url(params, password, server, "probably/not/a/valid/path/to/picture.png", &url);
    }
    if(errcode == DEFIANT_OK){
      fprintf(stdout, "%s\n%s\n", password, url);
      *urlp = url;
      *passwordp = strdup(password);
    } else {
      return errcode;
    }
    bf_free_params(params);
  }
  return DEFIANT_OK;
}

static int parseargs(int argc, char** argv, char** public_key_path, char** server, int* port, char** proxyserver, int* proxyport, int* proxytype){
  int retcode = DEFIANT_ARGS;
  *public_key_path = argv[1];
  *server = argv[2];
  *port = ( argc == 3 ? 80 : atoi(argv[3]) );
  char* proxyaddr =  ( argc >= 5 ? argv[4] : NULL );
  *proxytype = ( argc == 6 ? atoi(argv[5]) : -1 );
  
  if(proxyaddr != NULL){
    retcode = parseproxyaddress(proxyaddr, proxyserver, proxyport);

    if(retcode != DEFIANT_OK){
      fprintf(stderr, "Bad proxy address; should be  \"<server address>:<serverport>\": %s\n", proxyaddr);
      return retcode;
    }
  }

  if((*port != 80) && (*port != 443)){
    fprintf(stderr, "Bad port number; should be either 80 or 443: %d\n", *port);
    return retcode;
  }
  
  if(*proxytype != -1){
    const char* proxytypename = proxystring(*proxytype);
    if(proxytypename != NULL){
      fprintf(stderr, "Using proxy protocol: %s\n", proxytypename);
    } else {
      char *hints = proxyhints();
      fprintf(stderr, "Bad proxy type number %d\n", *proxytype);
      fprintf(stderr, "%s", hints);
      free(hints);
      return DEFIANT_ARGS;
    }
  }
  return DEFIANT_OK;
}




int parseproxyaddress(const char *proxyaddr, char **proxyserver, int *proxyport){
  int retval = DEFIANT_ARGS;
  if((proxyaddr != NULL) && (proxyserver != NULL) && (proxyport != NULL)){
    char* colon = strchr(proxyaddr, ':');
    if(colon != NULL){
      char* server = strdup(proxyaddr);
      int port = atoi(&colon[1]);
      colon = strchr(server, ':');
      if(colon != NULL){ *colon = '\0'; }
      *proxyserver = server;
      *proxyport = port;
      retval = DEFIANT_OK;
    } 
  }
  return retval;
}



int process_reply(FILE* public_key_fp, char* password, char* reply, size_t reply_size, int reply_type){
  int retcode = DEFIANT_DATA;
  char* encrypted_onion = NULL;
  size_t encrypted_onion_size = 0;
  onion_t onion = NULL;
  int onion_sz = 0;

  if(reply_type == DEFIANT_CONTENT_TYPE_UNKNOWN){
    fprintf(stderr, "process_reply: bad content type\n");
    return retcode;
  } else if(reply_type == DEFIANT_CONTENT_TYPE_JPEG){
    /* need to go look for it using outguess */
    retcode = extract(password, reply, reply_size,  &encrypted_onion, &encrypted_onion_size);
    if(retcode != DEFIANT_OK){
      return retcode;
    }
  } else if(reply_type == DEFIANT_CONTENT_TYPE_GIF){
    /* it's a naked onion */
    encrypted_onion = reply;
    encrypted_onion_size = reply_size;
  }

  
  retcode = defiant_lib_init(public_key_fp);
    
  if(retcode != DEFIANT_OK){ 
    fprintf(stderr, "defiant_lib_init(): retcode = %d\n", retcode);
  } else {
    
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
      retcode = verify_onion(public_key_fp, onion);
      if(retcode == DEFIANT_OK){
        fprintf(stderr, "onion VERIFIED\n");            
      } else {
        fprintf(stderr, "onion BOGUS\n");
      }
      info_onion(stderr, onion);
      free_onion(onion);
      onion = NULL;
    }
  }
  
  defiant_lib_cleanup();

  if(reply_type == DEFIANT_CONTENT_TYPE_JPEG){ free(encrypted_onion); }
  
  return retcode;

}
