#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "serverlib.h"
#include "serversql.h"
#include "defianterrors.h"
#include "onion.h"

static int debug = 1;
static int timing = 1;

static char *logfile = "../log/onionserver.log";



int main(int argc, char** argv){
  int success = 0;

  FILE* logfp = fopen(logfile, "a" );

  if(logfp != NULL){   
 
    flag(logfp, timing, "server commencing");
 
    char *query = server_fetchenv("QUERY_STRING");
 
    char *cookie = server_fetchenv("HTTP_COOKIE");
 
    char *private_key_path = server_fetchenv("DEFIANCE_PRIVATE_KEY_PATH");
    FILE* private_key_fp = NULL;
 
    char *public_key_path = server_fetchenv("DEFIANCE_PUBLIC_KEY_PATH"); 
    FILE* public_key_fp = NULL;
 
 
    if(debug){ 
      fprintf(logfp, "query = %s\n", query == NULL ? "NULL" : query);
      fprintf(logfp, "cookie = %s\n", cookie == NULL ? "NULL" : cookie);
      fprintf(logfp, "USER = %s\n", getenv("USER"));
      fprintf(logfp, "DEFIANT_CLASSPATH = %s\n", getenv("DEFIANT_CLASSPATH"));
      fprintf(logfp, "DEFIANT_ONIONFACTORY_NET_URL = %s\n", getenv("DEFIANT_ONIONFACTORY_NET_URL"));
      fprintf(logfp, "DEFIANT_DUMMY_CAPTCHA = %s\n", getenv("DEFIANT_DUMMY_CAPTCHA"));
      fprintf(logfp, "DEFIANCE_PRIVATE_KEY_PATH = %s\n", private_key_path);
      fprintf(logfp, "DEFIANCE_PUBLIC_KEY_PATH = %s\n", public_key_path);
    }

    if(private_key_path != NULL){
      private_key_fp = fopen(private_key_path, "r");
      if(private_key_fp == NULL){
        fprintf(logfp, "Could not open private key file %s: %s!\n",  private_key_path, strerror(errno));
        goto clean_up;
      }
    }
 
    if(public_key_path != NULL){
      public_key_fp = fopen(public_key_path, "r");
      if(public_key_fp == NULL){
        fprintf(logfp, "Could not open public key file %s: %s!\n",  public_key_path, strerror(errno));
        goto clean_up;
      }
    }

    
    /* just a toy protocol for the moment -- eventually the registration process would be more discriminatory */
    if((query != NULL) && (cookie != NULL)){
      
      MYSQL *mysql = sdb_connect(logfp);

      flag(logfp, timing, "mysql connection made");

      if(mysql != NULL){
        long int key_pair_id = -1;
        int errcode = validate_server(mysql, cookie, &key_pair_id);
        flag(logfp, timing, "validate_server done");
        fprintf(logfp, "validate_server = %d, key_pair_id = %ld\n", errcode, key_pair_id);
        if(errcode == DEFIANT_OK){
          long int server_id = sdb_fetch_server(mysql, key_pair_id);
          if(server_id == -1){
            fprintf(logfp, "New server with kp id %ld phoning home!\n",  key_pair_id);
            server_id = sdb_insert_server(mysql, key_pair_id);
          } else {
            fprintf(logfp, "Trusty server with kp id %ld  and server id = %ld phoning home!\n",  key_pair_id,  server_id);
          }
          flag(logfp, timing, "server registration done");


          if(debug){  fprintf(logfp, "server_id = %ld\n", server_id); }
          
          if(server_id > 0){
            
            sdb_increment_server(mysql, server_id);
            
            /* if(debug){ server_dumpenv(logfp); } */
            
            serve_onions(private_key_fp, public_key_fp, mysql, server_id, logfp, debug, timing);
            
            mysql_close(mysql);
            
            success = 1;
            
          }
          
        } else {
          flag(logfp, timing, "validate_server cookie bogus");
        }
      }
    }
    fclose(logfp);


  clean_up:

    free(cookie);
    free(query);

    free(private_key_path);
    free(public_key_path);

    if(private_key_fp != NULL){ fclose(private_key_fp); }
    if(public_key_fp != NULL){ fclose(public_key_fp); }

  }  

  if(!success){
    /* something went wrong */
    bApache();
  }
  
  return 0;
}


