#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "onion.h"
#include "defiantbf.h"
#include "defianterrors.h"
#include "defiantcookie.h"
#include "defiantclient.h"

#include "utils.h"
#include <curl/curl.h>

static onion_t fetch_onions(FILE *public_key_fp, char* cookie, char* onion_url, char* tor_proxy, long tor_proxy_port, FILE* logfp);


int main(int argc, char** argv){
  if(argc != 5){
    fprintf(stderr, "Usage: %s <private_key_file> <server> <portno> <defiance public key file>\n", argv[0]);
  } else {
    char *urlformat = "http://%s:%s/index.html?query=true";
    char url[1024];
    char* key_pair_path = argv[1];
    FILE *fp = fopen(key_pair_path, "rb");
    snprintf(url, 1024, urlformat, argv[2], argv[3]);
    if(fp != NULL){
      bf_key_pair_t* key_pair = NULL;
      int errcode = bf_read_key_pair(fp, &key_pair);          
      if(errcode == DEFIANT_OK){
        char* cookie = construct_cookie(key_pair);
        if(cookie != NULL){
          onion_t onions = NULL, collection = NULL;
          FILE *public_key_fp = fopen(argv[4], "r");
          if(public_key_fp == NULL){
            fprintf(stderr, "Could not open public key file %s: %s\n",  argv[4], strerror(errno));
            return 1;
          }
          fprintf(stdout, "Url = %s\nCookie = %s\n", url, cookie);
          onions = fetch_onions(public_key_fp, cookie, url, NULL, -1, stderr);
          if(onions != NULL){
            errcode = verify_onion(public_key_fp, onions);
            if(errcode == DEFIANT_OK){
              int i, onionc;
              onion_t* onionv = NULL;
              //info_onion(stdout, onions);
              collection = (onion_t)(ONION_DATA(onions));
              errcode = peel_collection_onion(collection, &onionc, &onionv);
              fprintf(stdout, "Payload verified, got %d onions, peeling:\n", onionc);
              if(onionc > 0){
                for(i = 0; i < onionc; i++){
                  onion_t onion = onionv[i];
                  info_onion(stdout, onion);
                  free(onion);
                }
              } else {
                fprintf(stderr, "No onions\n");
              }
              free(onionv);
            } else {
              fprintf(stderr, "Payload did NOT verify!\n");
            }
            free_onion(onions);
          } else {
            
          }
          free(cookie);
          bf_free_key_pair(key_pair);
        }
    } else {
        fprintf(stderr, "Couldn't load key_pair file: %s; errcode = %d\n", key_pair_path, errcode);
      }
    } else {
      fprintf(stderr, "Couldn't open key_pair file: %s because %s\n", key_pair_path, strerror(errno));
    }
  }
  return EXIT_SUCCESS;
}

onion_t fetch_onions(FILE *public_key_fp, char* cookie, char* onion_url, char* tor_proxy, long tor_proxy_port, FILE* logfp){
  onion_t retval = NULL;
  CURL* curlobj;
  curl_global_init(CURL_GLOBAL_ALL);
  curlobj = curl_easy_init();
  if(curlobj != NULL){
    CURLcode res, resl, rest;
    response resp = {NULL, 0};
    curl_easy_setopt(curlobj, CURLOPT_TIMEOUT, DEFIANT_CURL_TIMEOUT); 
    curl_easy_setopt(curlobj, CURLOPT_CONNECTTIMEOUT, DEFIANT_CURL_TIMEOUT); 
    //only use tor if the puppy is configured for it
    if((tor_proxy != NULL) && (tor_proxy_port != -1) ){
      curl_easy_setopt(curlobj, CURLOPT_PROXY, tor_proxy); 
      curl_easy_setopt(curlobj, CURLOPT_PROXYPORT, tor_proxy_port); 
      curl_easy_setopt(curlobj, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4A); 
    }
    curl_easy_setopt(curlobj, CURLOPT_URL, onion_url);
    curl_easy_setopt(curlobj, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curlobj, CURLOPT_WRITEDATA, (void *)&resp);
    if(cookie != NULL){ curl_easy_setopt(curlobj, CURLOPT_COOKIE, cookie);  }
    res = curl_easy_perform(curlobj);
    if(res != CURLE_OK){
      if(logfp != NULL)fprintf(logfp, "curl_easy_perform FAILED: curl code: %d\n", res);
    } else {
      double length = 0;
      char* type = NULL;
      resl = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &length);
      rest = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_TYPE, &type);
      if((resl ==  CURLE_OK) && (rest ==  CURLE_OK)){
        size_t header_length = (size_t)length;
        if(logfp != NULL){
          fprintf(logfp, "Content-Type: %s\n", type);
          fprintf(logfp, "Content-Length: %zd\n", header_length);
          fprintf(logfp, "resp = %zd bytes\n", resp.buffer_size);
        }
        if(header_length == resp.buffer_size){
          onion_t signed_onion = resp.buffer;
          /* onion2file("/tmp/onion", signed_onion); */
          int retcode = verify_onion(public_key_fp, signed_onion);
          if(retcode == DEFIANT_OK){
            retval = signed_onion;
          } else {
            if(logfp != NULL)fprintf(logfp, "verifying onion FAILED: %d\n", retcode);
          }
        }
      } else {
        if(logfp != NULL)fprintf(logfp, "fetching failed; ONLY got %zd bytes\n", resp.buffer_size);
      }
    }
    curl_easy_cleanup(curlobj);
  }
  curl_global_cleanup();
  return retval;
}

