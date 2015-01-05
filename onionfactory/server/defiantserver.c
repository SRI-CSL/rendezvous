#include "defiantserver.h"

#include <openssl/pem.h>

static EVP_PKEY *defiant_private_evp_pkey = NULL;

static int init_defiant_private_key(FILE* private_key_fp){
  if(private_key_fp == NULL){
    return DEFIANT_DATA;
  } else if(private_key_fp != NULL && defiant_private_evp_pkey == NULL){
    defiant_private_evp_pkey = PEM_read_PrivateKey(private_key_fp, &defiant_private_evp_pkey, NULL, NULL);
    if(defiant_private_evp_pkey == NULL){ return DEFIANT_DATA; }
  }
  return DEFIANT_OK;
}


int defiantserver_lib_init(FILE* private_key_fp){
  return init_defiant_private_key(private_key_fp);
}

void defiantserver_lib_cleanup(){
  if(defiant_private_evp_pkey != NULL){ 
    EVP_PKEY_free(defiant_private_evp_pkey);
    defiant_private_evp_pkey = NULL;
  }
}

static int defiant_sign_aux(EVP_PKEY *priv, char* data, int data_size, uchar** signaturep, unsigned int* signature_szp);

int defiant_sign(FILE* private_key_fp, char* data, int data_size, uchar** signaturep, unsigned int* signature_szp){
  int retcode = init_defiant_private_key(private_key_fp);
  if(retcode == DEFIANT_OK){
    return  defiant_sign_aux(defiant_private_evp_pkey, data, data_size, signaturep, signature_szp);
  }
  return DEFIANT_DATA;
}

int defiant_sign_aux(EVP_PKEY *priv, char* data, int data_size, uchar** signaturep, unsigned int* signature_szp){
  uchar* signature = NULL;
  int signature_size = EVP_PKEY_size(priv);
  unsigned int signature_sz = 0;
  EVP_MD_CTX sign_cxt;
  int retcode = EVP_SignInit(&sign_cxt, EVP_sha1());
  if(retcode != 1){
    return DEFIANT_CRYPTO;
  }
  retcode = EVP_SignUpdate(&sign_cxt, data, data_size);
  if(retcode != 1){
    return DEFIANT_CRYPTO;
  } else {
    signature = (uchar *)calloc(signature_size, sizeof(uchar));
    if(signature == NULL){
      return DEFIANT_MEMORY;
    }
    retcode = EVP_SignFinal(&sign_cxt, signature, &signature_sz, priv);
    if((retcode != 1) || ((int)signature_sz != signature_size)){
      return DEFIANT_CRYPTO;
    }
    *signaturep = signature;
    *signature_szp = signature_sz;
  }
  EVP_MD_CTX_cleanup(&sign_cxt);
  return DEFIANT_OK;
}

