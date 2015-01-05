#include <string.h>

#include "defiantrequest.h"
#include "defiantclient.h"
#include "utils.h"

/* these are google analytics markers, probably better in cookies */
static const char* markers[] =  { "_utma=", "_utmz=" }; 

static int generate_defiant_request_url_aux(bf_params_t *params, const char* password, const char* host, const char *path, char** request_urlp, int ssl);

int generate_defiant_ssl_request_url(bf_params_t *params, const char* password, const char* host, const char *path, char** request_urlp){
  return generate_defiant_request_url_aux(params, password, host, path, request_urlp, 1);
}

int generate_defiant_request_url(bf_params_t *params, const char* password, const char* host, const char *path, char** request_urlp){
  return generate_defiant_request_url_aux(params, password, host, path, request_urlp, 0);
}

//sigh jeroen's flags forced me to do this...
#define DEFIANT_REQUEST_URL_FORMAT  "%s%s/%s?%s%s&%s%s"


int generate_defiant_request_url_aux(bf_params_t *params, const char* password, const char* host, const char *path, char** request_urlp, int ssl){
  int status = DEFIANT_ARGS;
  if((password == NULL) || (host == NULL) || (path == NULL) || (request_urlp == NULL)){
    status = DEFIANT_ARGS;
  } else {
    char *b64U = NULL, *b64V = NULL;
    bf_ciphertext_t *ciphertext = NULL;
    int chars = 0, url_size = 0;
    char *url = NULL;

    *request_urlp = NULL;
    status = bf_encrypt(params, host, password, strlen(password), &ciphertext);
    if(status != DEFIANT_OK){  return status;  }

    status = bf_write_ciphertext(&b64U, &b64V, ciphertext, params);
    /* fprintf(stderr, "b64U = %s\nb64V = %s\n", b64U, b64V); */
    if(status != DEFIANT_OK){  return status;  }

    url = NULL;
    url_size = 0;

    while (1) {
      chars = snprintf(url, url_size,
                      "http%s://%s/%s?%s%s&%s%s",
                      ssl ? "s" : "", host, path, markers[0], b64U, markers[1], b64V);
      if (url_size != 0 && chars > url_size) {
         status = DEFIANT_DATA;
         break;
      } else if (url_size >= chars) {
         *request_urlp = url;
         status = DEFIANT_OK;
         break;
      } else if (url_size < chars) {
         url_size = chars + 1;
         url = (char *)calloc(url_size, sizeof(char));
         if (url == NULL) {
            status = DEFIANT_MEMORY;
         }
      }
    }

    bf_free_ciphertext(ciphertext);
    free(b64U);
    free(b64V);
  }
  return status;
}

static int parseblobs(char* str, char** blobAp, char**  blobBp){
  int retcode = DEFIANT_ARGS;
  if((str != NULL) || (blobAp != NULL) || (blobBp != NULL)){
    char *buffer = duplicate(str);
    if(buffer == NULL){
      retcode = DEFIANT_MEMORY;
    } else {
      char *startA = strstr(buffer, markers[0]); 
      char *startB = strstr(buffer, markers[1]); 
      if((startA == NULL) || (startB == NULL)){ 
        retcode = DEFIANT_ARGS; 
      } else {
        char *ampersand = strchr(startA, '&');
        if((ampersand == NULL) || (startB != (ampersand + 1))){ 
          retcode = DEFIANT_ARGS; 
        } else {
          int offsetA = (int)strlen(markers[0]);
          int offsetB = (int)strlen(markers[1]);
          char *blobA = &startA[offsetA];
          char *blobB = &startB[offsetB];
          *ampersand = '\0';
          *blobAp = duplicate(blobA);
          *blobBp = duplicate(blobB);
          retcode = DEFIANT_OK;
        }
      }
    }
    free(buffer);
  }
  return retcode;
}

int is_defiant_request_aux(bf_key_pair_t* key_pair, char* url, char** passwordp){
  if(url == NULL){
    return DEFIANT_ARGS;
  } else {
    char* blobA = NULL, *blobB = NULL;
    int retcode = parseblobs(url, &blobA, &blobB);
    if(retcode != DEFIANT_OK){
      return DEFIANT_DATA;
    } else {
      bf_ciphertext_t* ciphertext = NULL;
      retcode = bf_read_ciphertext(blobA, blobB, &ciphertext, key_pair);
      if(retcode == DEFIANT_OK){
        uchar buffer_out[DEFIANT_REQ_REP_PASSWORD_LENGTH + 1];
        buffer_out[DEFIANT_REQ_REP_PASSWORD_LENGTH] = '\0';
        retcode = bf_decrypt(key_pair, ciphertext, buffer_out, DEFIANT_REQ_REP_PASSWORD_LENGTH);
        if(retcode == DEFIANT_OK){
          *passwordp = duplicate((char *)buffer_out);
        }
        bf_free_ciphertext(ciphertext);
      } else {
        fprintf(stderr, "bad crypto");
      }
      free(blobA);
      free(blobB);
    }
    return retcode;
  }
}


int is_defiant_request(bf_key_pair_t* key_pair, char* url, char** passwordp){
  if((key_pair == NULL) || (url == NULL) || (passwordp == NULL)){
    return DEFIANT_ARGS;
  } else {
    return is_defiant_request_aux(key_pair, url, passwordp);
  }
}

