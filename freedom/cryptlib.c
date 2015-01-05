#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

#include "cryptlib.h"

char *apr_enbase64(request_rec *r, const uchar *input, int length, int *outlen){
  int retcode;
  BIO *bmem, *b64 = NULL;
  BUF_MEM *bptr;
  char *buff = NULL;
  if(length <= 0){ goto cleanup; }
  b64 = BIO_new(BIO_f_base64());
  if(b64 == NULL){ goto cleanup; }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  if(bmem == NULL){ goto cleanup; }
  b64 = BIO_push(b64, bmem);
  retcode = BIO_write(b64, input, length);
  if(retcode <= 0){ goto cleanup; }
  retcode = BIO_flush(b64);
  if(retcode != 1){ goto cleanup; }
  BIO_get_mem_ptr(b64, &bptr);
  buff = (char *)calloc(bptr->length + 1, sizeof(char));
  if(buff == NULL){  goto cleanup; }
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;
  if(outlen != NULL){ *outlen = bptr->length; }
  
 cleanup:
  if(b64 != NULL){ BIO_free_all(b64); }
  return buff;
}



uchar *apr_debase64(request_rec *r, const char *input, int *outlen){
  int bytes = 0;
  uchar *buffer = NULL;
  if(input != NULL){
    int length = strlen(input);
    BIO *b64  = NULL, *bmem = NULL; 
    b64 = BIO_new(BIO_f_base64());
    if(b64 != NULL){
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
      buffer = (uchar *)calloc(length, sizeof(uchar));
      if(buffer != NULL){
        bmem = BIO_new_mem_buf((char *)input, length);
        bmem = BIO_push(b64, bmem);
        bytes = BIO_read(bmem, buffer, length);
      }
      BIO_free_all(bmem);
    }
  }
  if(outlen != NULL){ *outlen = bytes; }
  return buffer;
}

