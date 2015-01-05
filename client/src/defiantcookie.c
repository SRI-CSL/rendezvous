#include <stdio.h>
#include <string.h>
#include "defiantcookie.h"
#include "defianterrors.h"
#include "defiantclient.h"
#include "makeargv.h"
#include "utils.h"

/* we use the base64 representation of the freedom_servers key_pair as a shared secret */
/* and use that to password encrypt a variable message of a fixed format               */

char *construct_cookie(bf_key_pair_t *key_pair){
  char *cookie = NULL;
  time_t tp;
  time(&tp);
  if(key_pair != NULL){ 
    char *pk = NULL, *qid = NULL, *did = NULL;
    int errcode = bf_key_pair_to_char64(&pk, &qid, &did, key_pair);
    if(errcode == DEFIANT_OK){
      int pk_len = strlen(pk);
      char *tstr = ctime(&tp);
      char* msg_format = "%s=%s";
      size_t msg_length = strlen(msg_format) + pk_len + strlen(tstr) + 1;
      char* msg = (char *)calloc(msg_length, sizeof(char));
      if(msg != NULL){
        int emsg_length = 0;
        uchar* emsg = NULL;
        snprintf(msg, msg_length, msg_format, pk, tstr);
        emsg = defiant_pwd_encrypt(did, (const uchar*)msg, strlen(msg), &emsg_length);
        if(emsg != NULL){
          int msg64_length = 0;
          char *msg64 = enbase64(emsg, emsg_length, &msg64_length);
          if(msg64 != NULL){
            char *cookie_format = "spk=%s; msg=%s;";
            size_t cookie_length = strlen(cookie_format) + pk_len + msg64_length + 1;
            cookie = (char *)calloc(cookie_length, sizeof(char));
            if(cookie != NULL){
              snprintf(cookie,  cookie_length, cookie_format, pk, msg64);
            }
          }
          free(msg64);
        }
        free(emsg);
      }
      free(msg);
      free(pk);
      free(qid);
      free(did);
    }
  }
  return cookie;
}


char *public_key_cookie(char *cookie){
  char *public_key = NULL;
  if(cookie != NULL){
    char** ckv = NULL;
    int ckc = makeargv(cookie, " ;", &ckv);
    if((ckc == 2) && (strstr(ckv[0], "spk=") != NULL)){
      public_key = duplicate(&(ckv[0][strlen("spk=")]));
    }
    freeargv(ckc, ckv);
  }
  return public_key;
}

int validate_cookie_64(char* cookie, char* pk, char* did){
  int retval = DEFIANT_ARGS;
  if((cookie != NULL) &&  (pk != NULL) &&  (did != NULL)){
    char** ckv = NULL;
    int ckc = makeargv(cookie, " ;", &ckv);
    if((ckc == 2) && (strstr(ckv[1], "msg=") != NULL)){
      char* msg64 = &(ckv[1][strlen("spk=")]);
      int emsg_length = 0, msg_length = 0;
      uchar* emsg = debase64(msg64, &emsg_length);
      char* msg = (char *)defiant_pwd_decrypt(did, emsg, emsg_length, &msg_length);
      if(msg != NULL){
        /* fprintf(stderr, "message = \"%s\"\n", (char *)msg); */
        /* could be picky about times here too if we wanted to be */
        if(strstr(msg, pk) != NULL){
          retval = DEFIANT_OK;
        } else {
          retval = DEFIANT_DATA;
        }
      }
      free(emsg);
      free(msg);
    }
    freeargv(ckc, ckv);
  }
  return retval;


}

int validate_cookie(char* cookie, bf_key_pair_t *key_pair){
  int retval = DEFIANT_ARGS;
  if((cookie != NULL) &&  (key_pair != NULL)){
    char *pk = NULL, *qid = NULL, *did = NULL;
    int errcode = bf_key_pair_to_char64(&pk, &qid, &did, key_pair);
    if(errcode == DEFIANT_OK){
      retval = validate_cookie_64(cookie, pk, did);
      free(pk);
      free(qid);
      free(did);
    }
  }
  return retval;
}

