#include "nep.h"
#include "utils.h"
#include "defiantconstants.h"
#include "defiantclient.h"
#include "defianterrors.h"
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "platform.h"

char* parse_nep(char* data){
  char* nep = NULL;
  if(data != NULL){
    char* start = strrchr(data, '{');
    if(start != NULL){
      char * end = strrchr(data, '}');
      if(end != NULL){
        end[1] = '\0';
        nep = duplicate(start);
      }
    }
  }
  /* don't let jeroen's css masquerade as a nep */
  if((nep == NULL)                        ||
     (strstr(nep, "initial") == NULL)     ||
     (strstr(nep, "redirect") == NULL)    ||
     (strstr(nep, "wait") == NULL)        ||
     (strstr(nep, "window") == NULL)      ||
     (strstr(nep, "passphrase") == NULL)){
    free(nep);
    nep = NULL;
  }
  return nep;
}


static int isc_get_nep(char** nepp, char* uri, FILE* logfp, int debug);
static int sri_get_nep(char** nepp, char* uri, FILE* logfp, int debug);

int get_nep(char** nepp, FILE* logfp, int debug){
  char* net_url = getenv("DEFIANT_ONIONFACTORY_NET_URL");
  if((net_url != NULL) && strcmp("", net_url)){
    return isc_get_nep(nepp, net_url, logfp, debug);
  } else {
    return sri_get_nep(nepp, net_url, logfp, debug);
  }
}


static char neonep[] = 
  "{\n"
  "\"initial\": \"192.0.2.141\",\n"
  "\"redirect\": \"192.0.2.75\",\n"
  "\"wait\": 4,\n"
  "\"window\": 8,\n"
  "\"passphrase\": \"d4e2bbeefd15e7dc5a6c8874\"\n"
  "}\n";

int sri_get_nep(char** nepp, char* uri, FILE* logfp, int debug){
  int retcode = DEFIANT_ARGS;
  if((nepp != NULL) && (logfp != NULL)){
    if(debug){
      fprintf(logfp, "DEFIANT_ONIONFACTORY_NET_URL not set, faking it.\n");
    }
    *nepp = duplicate(neonep);
    retcode = DEFIANT_OK;
  }
  return retcode;
}

int isc_get_nep(char** nepp, char* uri, FILE* logfp, int debug){
  int retcode = DEFIANT_ARGS;
  if((nepp == NULL) || (logfp == NULL) || (uri == NULL)){
    return retcode;
  } else {
    CURL* curlobj;
    curl_global_init(CURL_GLOBAL_ALL);
    curlobj = curl_easy_init();
    if(curlobj != NULL){
      CURLcode res, resl;
      response resp = {NULL, 0};
      curl_easy_setopt(curlobj, CURLOPT_TIMEOUT, DEFIANT_CURL_TIMEOUT); 
      curl_easy_setopt(curlobj, CURLOPT_CONNECTTIMEOUT, DEFIANT_CURL_TIMEOUT); 
      curl_easy_setopt(curlobj, CURLOPT_URL, uri);
      curl_easy_setopt(curlobj, CURLOPT_WRITEFUNCTION, callback);
      curl_easy_setopt(curlobj, CURLOPT_WRITEDATA, (void *)&resp);
      res = curl_easy_perform(curlobj);
      if(res != CURLE_OK){
        fprintf(logfp, "get_nep: curl_easy_perform FAILED: curl code: %d\n", res);
    } else {
        double length = 0;
        char* type = NULL;

        resl = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_TYPE, &type);
        if ((resl != CURLE_OK || type == NULL) && debug){
            fprintf(logfp, "get_nep: Content-Type was not set by server?! (%u)\n", resl);
	}

        resl = curl_easy_getinfo(curlobj, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &length);
        if (resl == CURLE_OK){
          size_t header_length = (size_t)length;
          if (debug){
            fprintf(logfp, "get_nep: Content-Type: %s\n", type);
            fprintf(logfp, "get_nep: Content-Length: %" PRIsizet "\n", header_length);
            fprintf(logfp, "get_nep: resp = %" PRIsizet " bytes\n", resp.buffer_size);
          }

          if (header_length == resp.buffer_size){
            char* nep = parse_nep(resp.buffer);
            if (nep != NULL){
              *nepp = nep;
              fprintf(logfp, "get_nep: %s\n", nep);
              retcode = DEFIANT_OK;
            } else {
              fprintf(logfp, "get_nep: nep response failed to parse: %s\n", resp.buffer);  
              retcode = DEFIANT_INTERNET;
            }
            free(resp.buffer);

          } else {
            fprintf(logfp, "get_nep: ONLY got %" PRIsizet " bytes, expecting %" PRIsizet "\n", resp.buffer_size, header_length);
            retcode = DEFIANT_INTERNET;
          }
        } else {
          fprintf(logfp, "get_nep: curl_easy_getinfo FAILED: curl code: %d\n", resl);
          retcode = DEFIANT_INTERNET;
        } 
      }
      curl_easy_cleanup(curlobj);
    } else {
      retcode = DEFIANT_INTERNET;
    }
    curl_global_cleanup();
    return retcode;
  }
}




