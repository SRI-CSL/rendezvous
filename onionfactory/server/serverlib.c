#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "onion.h"
#include "nep.h"
#include "defiantclient.h"
#include "defiantcookie.h"
#include "serverlib.h"
#include "serversql.h"
#include "utils.h"
#include "onionlib.h"

#define DOZEN 12

void flag(FILE* logfp, int debug, char* msg){
  if(!debug || logfp == NULL){
    return;
  } else {
    time_t now = time(NULL);
    fprintf(logfp, "[%s] %s\n",  timestamp(&now), msg);
    fflush(logfp);
  }
}

char* server_fetchenv(char* key){
  if(key != NULL){ 
    return duplicate(getenv(key));
  }
  return NULL;
}

static char apache[] = 
  "Content-Type: text/html\r\n\r\n"
  "<html><body><h1>It works!</h1>"
  "<p>This is the default web page for this server.</p>"
  "<p>The web server software is running but no content has been added, yet.</p>"
  "</body></html>"  ;

void bApache(){ fprintf(stdout,  "%s", apache); }

static onion_t make_payload(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int *onion_ids, int nepc, FILE* logfp, int debug){
  if(nepc > 0){
    int i;
    char** nepv = (char**)calloc(nepc, sizeof(char*));
    for(i = 0; i < nepc; i++){
      char *nep = NULL;
      fprintf(logfp, "Get NEP[%d/%d]\n", i, nepc);
      int errcode = get_nep(&nep, logfp, debug);
      fprintf(logfp, "Get NEP[%d/%d] = %d\n", i, nepc, errcode);
      if(errcode != DEFIANT_OK){
        fprintf(logfp, "Getting nep failed: %d\n", errcode);
        return NULL;
      }
      nepv[i] = nep;
    }
    fprintf(logfp, "Got %d neps\n", nepc);
    onion_t signed_collection = NULL;
    int errcode = defiant_lib_init(public_key_fp);
    fprintf(logfp, "Defiant Lib Initialized, packing neps\n");
    srand(time(NULL));
    errcode = pack_neps(private_key_fp, public_key_fp, mysql, onion_ids, nepc, nepv, &signed_collection, logfp, debug);
    fprintf(logfp, "NEPS packed (%d), cleaning up\n", errcode);
    for(i = 0; i < nepc; i++){ free(nepv[i]); }
    free(nepv);
    if(errcode == DEFIANT_OK){
      return signed_collection;
    }
  }
  return NULL;
}

void serve_onions(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int server_id, FILE* logfp, int debug, int timing){
  onion_t signed_collection = NULL;
  int errcode = defiant_lib_init(public_key_fp);
  if(errcode != DEFIANT_OK){ 
    fprintf(logfp, "defiant_lib_init(): errcode = %d\n", errcode);
    bApache();
  } else {
    int index;
    time_t now = time(NULL);
    long int onion_ids[DOZEN];
    srand(now);

    flag(logfp, timing, "making payload");

    signed_collection = make_payload(private_key_fp, public_key_fp, mysql, onion_ids, DOZEN, logfp, debug);

    flag(logfp, timing, "payload  done");

    if(signed_collection != NULL){ 
      
      for(index = 0; index < DOZEN; index++){
        long int onion_id = onion_ids[index];
        long int slot = sdb_insert_server_onion_map(mysql, server_id, onion_id);
        if(debug && (logfp != NULL)){ fprintf(logfp, "%ld maps server %ld to onion %ld!\n", slot, server_id, onion_id); }
      }
      
      flag(logfp, timing, "onions inserted");
      
      size_t onion_size = ONION_SIZE(signed_collection);
      size_t bytes_written = 0;
      now = time(NULL);
      fprintf(stdout, "Content-Length: %zd\n", onion_size);
      fprintf(stdout, "Content-Type: image/gif\r\n\r\n");
      bytes_written = fwrite(signed_collection, sizeof(char), onion_size, stdout);
      fprintf(logfp, "[%s] served onion collection with %d onions; %zd of %zd bytes\n",  timestamp(&now), DOZEN, bytes_written, onion_size);
    }

    defiant_lib_cleanup();
    free(signed_collection);
  }
}


extern char **environ;

void server_dumpenv(FILE* logfp){
  int i;
  for(i = 0; environ[i] != NULL; i++){
    fprintf(logfp,"environ[%d]:  %s\n", i, environ[i]);
  }
}



int validate_server(MYSQL *mysql, char *cookie, long int *key_pair_idp){
  int retval = DEFIANT_ARGS;
  if(key_pair_idp != NULL){
    char* public_key = public_key_cookie(cookie);
    if(public_key != NULL){
      long int key_pair_id = sdb_fetch_key_pair_id(mysql, public_key);  
      if(key_pair_id != -1){
        char *did64 = sdb_fetch_private_key(mysql, key_pair_id);  
        if(did64 != NULL){
          retval = validate_cookie_64(cookie, public_key, did64);
          if(retval == DEFIANT_OK){
            *key_pair_idp = key_pair_id;
          }
          free(did64);
        }
      }
      free(public_key);
    }
  }
  return retval;
}
