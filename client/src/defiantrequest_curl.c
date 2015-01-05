#include <string.h>
#include <curl/curl.h>

#include "defiantrequest.h"
#include "defiantclient.h"
#include "utils.h"

const char* proxystring(int code){
  switch(code){
  case CURLPROXY_HTTP: return "CURLPROXY_HTTP";
  case CURLPROXY_HTTP_1_0: return "CURLPROXY_HTTP_1_0";
  case CURLPROXY_SOCKS4: return "CURLPROXY_SOCKS4";
  case CURLPROXY_SOCKS5: return "CURLPROXY_SOCKS5";
  case CURLPROXY_SOCKS4A: return "CURLPROXY_SOCKS4A";
  case CURLPROXY_SOCKS5_HOSTNAME: return "CURLPROXY_SOCKS5_HOSTNAME";
  default: return NULL;
  }
}

char *proxyhints(void){
  char usage[] =
    "\tCURLPROXY_HTTP            = 0, use HTTP/1.1\n"
    "\tCURLPROXY_HTTP_1_0        = 1, use HTTP/1.0\n"
    "\tCURLPROXY_SOCKS4          = 4, use SOCKS 4\n"
    "\tCURLPROXY_SOCKS5          = 5, use SOCKS 5\n"
    "\tCURLPROXY_SOCKS4A         = 6, use SOCKS 4A\n"
    "\tCURLPROXY_SOCKS5_HOSTNAME = 7, use the SOCKS5 protocol but pass along the host name rather than the IP address.\n";
  return strdup(usage);
}



int send_request(const char* request, int mode, const char* proxyserver, int proxyport, int proxytype, char**reply, size_t* reply_size, int *reply_type){
  int retcode = DEFIANT_ARGS;
  if((reply == NULL) || (reply_size == NULL) || (reply_type == NULL)){
    return retcode;
  } else {
    CURL* curlobj;
    curl_global_init(CURL_GLOBAL_ALL);
    curlobj = curl_easy_init();
    if(curlobj != NULL){
      CURLcode res, resl, rest;
      response resp = {NULL, 0};
      curl_easy_setopt(curlobj, CURLOPT_TIMEOUT, DEFIANT_CURL_TIMEOUT); 
      curl_easy_setopt(curlobj, CURLOPT_CONNECTTIMEOUT, DEFIANT_CURL_TIMEOUT); 
      if(1){
        fprintf(stderr, "request = %s\n", request);
        fprintf(stderr, "proxyserver = %s\n", proxyserver);
        fprintf(stderr, "proxyport = %d\n", proxyport);
        fprintf(stderr, "proxytype = %d\n", proxytype);
      }
      //only use proxy if the puppy is requested
      if((proxyserver != NULL) && (proxyport != 0) && (proxytype != -1)){
        curl_easy_setopt(curlobj, CURLOPT_PROXY, proxyserver); 
        curl_easy_setopt(curlobj, CURLOPT_PROXYPORT, proxyport); 
        curl_easy_setopt(curlobj, CURLOPT_PROXYTYPE, proxytype); 
      }
      if(mode){
        curl_easy_setopt(curlobj, CURLOPT_SSL_VERIFYPEER, 0);
      }
      curl_easy_setopt(curlobj, CURLOPT_URL, request);
      curl_easy_setopt(curlobj, CURLOPT_WRITEFUNCTION, callback);
      curl_easy_setopt(curlobj, CURLOPT_WRITEDATA, (void *)&resp);
      res = curl_easy_perform(curlobj);
      if(res != CURLE_OK){
        const char* cerror = curl_easy_strerror(res);
        fprintf(stderr, "curl_easy_perform FAILED: curl code: %d curl strerror: %s\n", res, cerror);
        retcode = DEFIANT_INTERNET;
      } else {
        double length = 0;
        char* type = NULL;
        resl = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &length);
        rest = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_TYPE, &type);
        if((resl ==  CURLE_OK) && (rest ==  CURLE_OK)){
          size_t header_length = (size_t)length;
          if(1){
            fprintf(stderr, "Content-Type: %s\n", type);
            fprintf(stderr, "Content-Length: %" PRIsizet "\n", header_length);
            fprintf(stderr, "resp = %" PRIsizet " bytes\n", resp.buffer_size);
          }
          if(header_length == resp.buffer_size){
            *reply = resp.buffer;
            *reply_size = resp.buffer_size;
            if(type == NULL){
              *reply_type = DEFIANT_CONTENT_TYPE_UNKNOWN;
            } else if((type != NULL) &&  strstr(type, "image/jpeg") != NULL){  
              *reply_type = DEFIANT_CONTENT_TYPE_JPEG; 
            } else if((type != NULL) &&  strstr(type, "image/gif") != NULL){  
              *reply_type = DEFIANT_CONTENT_TYPE_GIF; 
            }
            retcode = DEFIANT_OK;
          } else {
            fprintf(stderr, "fetching failed; ONLY got %" PRIsizet " bytes\n", resp.buffer_size);
            retcode = DEFIANT_INTERNET;
          }
        } else {
          fprintf(stderr, "headers no good; content_length: %s content_type: %s\n", curl_easy_strerror(resl), curl_easy_strerror(rest));
          retcode = DEFIANT_INTERNET;
        }
      }
      curl_easy_cleanup(curlobj);
    }
    curl_global_cleanup();
  }
  return retcode;
}
