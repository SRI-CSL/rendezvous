#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/sha.h>

#include "onionlib.h"
#include "defiantclient.h"
#include "defiantserver.h"

/* flick off to leave the images around */
#define UNLINK 1

int make_signed_onion(FILE* private_key_fp, size_t dsz, void *d, onion_t *onionp){
  uchar *signature = NULL;
  unsigned int signature_sz = 0;
  int retcode = defiant_sign(private_key_fp, d, dsz, &signature, &signature_sz);
  if(retcode == DEFIANT_OK){
    onion_t signed_onion = alloc_onion(SIGNED, signature_sz, dsz, signature, d);
    *onionp = signed_onion;
    free(signature);
  }
  return retcode;
}

int make_onion_collection(uint32_t onionc, onion_t* onionv, onion_t *onionp){
  if((onionv == NULL) || (onionp == NULL)){
    return DEFIANT_ARGS;
  } else {
    size_t weight = 0,  offset = 0;
    int i;
    onion_t collection = NULL;
    for(i = 0; i < onionc; i++){
      onion_t onion = onionv[i];
      weight += ONION_SIZE(onion);
    }
    collection = alloc_onion(COLLECTION, sizeof(uint32_t), weight, NULL, NULL);
    if(collection != NULL){
      char *pbuff = (char *)ONION_PUZZLE(collection);
      char *dbuff = (char *)ONION_DATA(collection);
      uint32_t onionc_net = htonl(onionc);
      memcpy(pbuff, &onionc_net, sizeof(onionc_net));
      for(i = 0; i < onionc; i++){
        char *d = onionv[i];
        size_t  dsz = ONION_SIZE(d);
        memcpy(&dbuff[offset], d, dsz);
        offset += dsz;
      }
      *onionp = collection;
      return DEFIANT_OK;
    } else {
      return DEFIANT_MEMORY;
    }
  }
}

static long int sdb_insert_onion(MYSQL *mysql, size_t size, char *pow_pwd, char* captcha_pwd, char* nep, FILE* logfp, int debug){
  long int retval = -1;
  if((mysql != NULL) && (pow_pwd != NULL) && (captcha_pwd != NULL) && (nep != NULL)){
    char *format = "insert into onion (onion_size, pow_password, captcha_password, nep) values (%ld, '%s', '%s', '%s')";
    size_t query_length = strlen(format) + SIZE_T_DIGITS + strlen(pow_pwd) + strlen(captcha_pwd)+ strlen(nep) + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      int retcode;
      snprintf(query, query_length, format, size, pow_pwd, captcha_pwd, nep);
      if(debug && (logfp != NULL)){ fprintf(logfp, "query = %s\n", query); }
      retcode = mysql_query(mysql, query);
      if(debug && (logfp != NULL)){ fprintf(logfp, "retcode = %d\n", retcode); }
      if(retcode == 0){
        retval = mysql_insert_id(mysql);
        if(debug && (logfp != NULL)){ fprintf(logfp, "retcode = %d onion_id = %ld\n", retcode, retval); }
      }
      free(query);
    }
  }
  return retval;
}


static void demohack(char *buff, int bufsz){
  char* dummy = getenv("DEFIANT_DUMMY_CAPTCHA");
  if((buff != NULL) && (dummy != NULL)){
    int len = strlen(dummy);
    len = len < bufsz ? len : bufsz - 1;
    memset(buff, '\0', bufsz);
    memcpy(buff, dummy, len); 
  }
}


int pack_nep(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int *onion_idp, char* nep, onion_t* signedp, FILE* logfp, int debug){
  if((nep == NULL) || (signedp == NULL)){
    if(logfp != NULL)fprintf(logfp, "pack_nep: bad args %p %p\n", (void *)nep, (void *)signedp);
    return DEFIANT_ARGS;
  } else {
    onion_t base_onion = NULL, pow_onion = NULL, captcha_onion  = NULL, signed_onion  = NULL; 
    size_t dsz = strlen(nep) + 1; /* keep the nep NULL-terminated */
    int errcode = make_onion(BASE, 0, dsz, NULL, (void *)nep, &base_onion);
    if(errcode != DEFIANT_OK){
      if(logfp != NULL)fprintf(logfp, "pack_nep:  make_onion FAILED -  errcode = %d\n", errcode);
      return errcode;
    } else {
      char password[DEFIANT_CLIENT_PASSWORD_LENGTH];
      char cpassword[DEFIANT_CAPTCHA_PASSWORD_LENGTH];
      /* make the captcha password */
      randomPasswordEx(cpassword, DEFIANT_CAPTCHA_PASSWORD_LENGTH, 0);
      /* DEMO HACK 4 RATPAC    */
      demohack(cpassword, DEFIANT_CAPTCHA_PASSWORD_LENGTH);
      /* make the pow password */
      randomPassword(password, DEFIANT_CLIENT_PASSWORD_LENGTH);
      /* keep the search space manageable */
      //NON DEMO:      password[0] =  password[1]  = 'a';
      //DEMO:
      password[0] =  password[1]  = password[2]  = 'a';
      errcode = make_pow_onion_aux(password, ONION_SIZE(base_onion), (void *)base_onion, &pow_onion);
      if(errcode != DEFIANT_OK){  
        if(logfp != NULL)fprintf(logfp, "pack_nep: make_pow_onion_aux FAILED -  errcode = %d\n", errcode);
        return errcode;
      }
      errcode = check_pow_onion(password, pow_onion, base_onion);
      if(errcode != DEFIANT_OK){  
        if(logfp != NULL)fprintf(logfp, "pack_nep: check_pow_onion FAILED -  errcode = %d\n", errcode);
        return errcode;
      }
      errcode = make_captcha_onion_aux(cpassword, ONION_SIZE(pow_onion), (void *)pow_onion, &captcha_onion);
      if(errcode != DEFIANT_OK){  
        if(logfp != NULL)fprintf(logfp, "pack_nep: make_captcha_onion_aux FAILED -  errcode = %d\n", errcode);
        return errcode;
      }
      errcode = check_captcha_onion(cpassword, captcha_onion, pow_onion);
      if(errcode != DEFIANT_OK){  
        if(logfp != NULL)fprintf(logfp, "pack_nep: check_captcha_onion FAILED -  errcode = %d\n", errcode);
        return errcode;
      }
      errcode = make_signed_onion(private_key_fp, ONION_SIZE(captcha_onion), (void *)captcha_onion, &signed_onion); 
      if(errcode != DEFIANT_OK){  
        if(logfp != NULL)fprintf(logfp, "pack_nep: make_signed_onion FAILED -  errcode = %d\n", errcode);
        return errcode;
      }
      errcode = check_signed_onion(public_key_fp, signed_onion, captcha_onion);
      if(errcode != DEFIANT_OK){  
        if(logfp != NULL)fprintf(logfp, "pack_nep: check_signed_onion FAILED -  errcode = %d\n", errcode);
        return errcode;
      }

      if((mysql != NULL) && (onion_idp != NULL)){
        size_t produce = ONION_SIZE(signed_onion);
        *onion_idp = sdb_insert_onion(mysql, produce, password, cpassword, nep, logfp, debug);
      }

      if(debug && (logfp != NULL)){
        time_t now = time(NULL);
        char* stamp = timestamp(&now);
        size_t produce = ONION_SIZE(signed_onion);
        fprintf(logfp, "[%s] <%zd> signed onion size           = %zd\n",  stamp, produce, produce);
        fprintf(logfp, "[%s] <%zd> captcha onion size          = %zd\n",  stamp, produce, ONION_SIZE(captcha_onion));
        fprintf(logfp, "[%s] <%zd> pow onion size              = %zd\n",  stamp, produce, ONION_SIZE(pow_onion));
        fprintf(logfp, "[%s] <%zd> base onion size             = %zd\n",  stamp, produce, ONION_SIZE(base_onion));
        fprintf(logfp, "[%s] <%zd> pow password                = %s\n",   stamp, produce, password);
        fprintf(logfp, "[%s] <%zd> captcha password            = %s\n",   stamp, produce, cpassword); 
      }

      free_onion(base_onion);        
      free_onion(pow_onion);
      free_onion(captcha_onion);
      *signedp = signed_onion;
      return DEFIANT_OK;
    }
  }
}



int pack_neps(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int *onion_ids, int nepc, char** nepv, onion_t* signedp, FILE* logfp, int debug){
  if(logfp != NULL)fprintf(logfp, "pack_neps\n");
  if((nepc < 0) || (nepv == NULL) || (signedp == NULL)){
    if(logfp != NULL)fprintf(logfp, "pack_neps - missing arguments\n");
    return DEFIANT_ARGS;
  } else {
    int i, onionc = nepc;
    onion_t collection = NULL;
    onion_t signed_collection = NULL;
    int errcode = defiant_lib_init(public_key_fp);
    if(logfp != NULL)fprintf(logfp, "pack_neps - allocating memory\n");
    onion_t *onionv = (onion_t *)calloc(onionc, sizeof(onion_t));
    if (onionv == NULL) {
      if(logfp != NULL)fprintf(logfp, "pack_neps - no memory!\n");
      return DEFIANT_MEMORY;
          
    }
    for(i = 0; i < onionc; i++){
      if(logfp != NULL)fprintf(logfp, "pack_neps - nep %d/%d!\n", i, onionc);
      errcode = pack_nep(private_key_fp, public_key_fp, mysql, &onion_ids[i], nepv[i], &onionv[i], logfp, debug);
      if(errcode != DEFIANT_OK){ return errcode; }
    }
    if(logfp != NULL)fprintf(logfp, "pack_neps - neps packed, making collection\n");
    errcode =  make_onion_collection(onionc, onionv, &collection);
    info_onion(logfp, collection);
    if(logfp != NULL)fprintf(logfp, "pack_neps - collection made, signing onion\n");
    errcode = make_signed_onion(private_key_fp, ONION_SIZE(collection), (void *)collection, &signed_collection); 
    if(errcode != DEFIANT_OK){  
      if(logfp != NULL)fprintf(logfp, "pack_neps: make_signed_onion FAILED -  errcode = %d\n", errcode);
      return errcode;
    }
    errcode = check_signed_onion(public_key_fp, signed_collection, collection);
    if(errcode != DEFIANT_OK){  
      if(logfp != NULL)fprintf(logfp, "pack_neps: check_signed_onion FAILED -  errcode = %d\n", errcode);
      return errcode;
    }
    //info_onion(logfp, signed_collection);
    for(i = 0; i < onionc; i++){ free(onionv[i]); }
    free(onionv);
    free(collection);

    *signedp = signed_collection;
    return DEFIANT_OK;
  }
}
