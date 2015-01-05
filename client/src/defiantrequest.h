#ifndef _DEFIANTREQUEST_H
#define _DEFIANTREQUEST_H

#include "platform.h"
#include "defiantbf.h"

typedef enum {
  DEFIANT_CONTENT_TYPE_UNKNOWN = 0,  
  DEFIANT_CONTENT_TYPE_JPEG = 1,
  DEFIANT_CONTENT_TYPE_GIF = 2
} defiant_contentype;  


//post-ratpac-cleanup #ifdef FREEDOM_APACHE_MODULE 
//post-ratpac-cleanup #include "apr_uri.h"
//post-ratpac-cleanup #endif

#ifdef __cplusplus
extern "C" {
#endif

extern int generate_defiant_request_url(bf_params_t *params, const char* password, const char* host, const char *path, char** request_urlp);
  int generate_defiant_ssl_request_url(bf_params_t *params, const char* password, const char* host, const char *path, char** request_urlp);
 
  int is_defiant_request_aux(bf_key_pair_t* key_pair, char* url, char** passwordp);
  int is_defiant_request(bf_key_pair_t* key_pair, char* url, char** passwordp);



  //curl lib stuff (used by the qt app to tunnel with curveball)
  const char* proxystring(int code);
  char* proxyhints(void);

  int send_request(const char* request, int mode, const char* proxyserver, int proxyport, int proxytype, char**reply, size_t* reply_size, int* reply_type);




#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */


#endif /* _DEFIANTREQUEST_H */
