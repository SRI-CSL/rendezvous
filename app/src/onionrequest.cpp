#include "onionrequest.h"
#include "util.h"
#include "defiantclient.h"
#include "defiantrequest.h"
#include "defiantbf.h"
#include "defiant_params.h"
#include <stdlib.h>


OnionRequest::OnionRequest(QString& server, bool s){
  char *request = NULL;
  bf_params_t *params =  NULL;
  int defcode;
  secure = s;
  defcode = bf_char64_to_params(defiant_params_P, defiant_params_Ppub, &params);
  if(defcode == DEFIANT_OK){

    randomPasswordEx(password, DEFIANT_REQ_REP_PASSWORD_LENGTH + 1, 0);
    randomPath();
    
    Util::debug() <<  " OnionRequest: password  = " << password << " of length " << strlen(password);
    if(secure){
      defcode = generate_defiant_ssl_request_url(params, password, server.toAscii().data(), path, &request);
    } else {
      defcode = generate_defiant_request_url(params, password, server.toAscii().data(), path, &request);
    }
    Util::debug() << " OnionRequest::request " <<  request ;

    if(defcode == DEFIANT_OK){
      QString uri(request);
      free(request);
      this->setUrl(uri);
    }
  }
}



/* this can be elaborated ad infinitum */
void OnionRequest::randomPath(){
  int r = rand();
  //look like flickr for today:
  snprintf(path, 1024, "photos/26907150@N08/%d/lightbox", r);
}
