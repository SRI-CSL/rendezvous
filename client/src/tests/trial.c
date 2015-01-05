#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defiantclient.h" 
#include "makeargv.h"
#include "cweb.h" 

/* char *url = "http://bit.ly/qijNgL";  */

char *url = "http://bit.ly/pzga8T";

#define TRIAL_DEBUG 1


int main(int argc, char** argv){
  int retcode;
  long httpCode;
  char* redirectURL = NULL;
  if(argc == 2){
    url = argv[1];
  }
  retcode = getRedirect(url, &httpCode, &redirectURL);
  if(retcode){
    int urlc = 0;
    char** urlv = NULL;
    if(TRIAL_DEBUG){ fprintf(stderr, "%ld %s\n", httpCode, redirectURL); }
    urlc = makeargv(redirectURL, "&;", &urlv);
    if(TRIAL_DEBUG){ printargv(stdout, "urlv", urlc, urlv);}
    if(urlc > 3){
      char* one = fetchv("_zyx=", urlc, urlv);
      char* two = fetchv("_zyy=", urlc, urlv);
      char* three = fetchv("_zyz=", urlc, urlv);
      if(TRIAL_DEBUG){ fprintf(stdout, "./tool %s %s %s\n",  one, two, three); }
      if((one != NULL) && (two != NULL) && (three != NULL)){
        char * next_hop = defiant_pow(one, two, three, NULL);
        fprintf(stdout, "next_hop = %s\n",  next_hop);
        free(next_hop);
      }
    }
  } else {
    fprintf(stderr, "getRedirect failed (%ld)\n", httpCode);
  }
  free(redirectURL);
  return 0;
}

