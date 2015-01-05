#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>


static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream){
  size_t realsize = size * nmemb;
  return realsize;
}

int getRedirect(char* url, long* httpCode, char** redirectUrl){
  int retval = 0;
  if((url == NULL) || (url == NULL) ||  (redirectUrl == NULL) ){ 
    return retval; 
  } else {
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
      /* set the url to fetch */
      curl_easy_setopt(curl, CURLOPT_URL, url);
      
      /* no progress meter please */ 
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
      
      /* send all data to this function: /dev/null  */ 
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
      
      res = curl_easy_perform(curl);
      
      if(CURLE_OK == res ){
        res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, httpCode);
        if(CURLE_OK == res){ 
          char *rurl = NULL;
          res = curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &rurl);
          if((CURLE_OK == res) && (rurl != NULL)){ 
            /* valgrind doesn't like the string that comes back from curl: rurl */
            char* redirect = (char  *) calloc(strlen(rurl) + 1, sizeof(char*));
            strcpy(redirect, rurl);
            *redirectUrl = redirect;
            /* success */
            retval = 1;
          }
        }
      }
      /*  cleanup */ 
      curl_easy_cleanup(curl);
    }
  }
  return retval;
}

