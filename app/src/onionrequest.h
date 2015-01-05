#ifndef ONIONREQUEST_H
#define ONIONREQUEST_H

#include <QUrl>

#include "defiantclient.h"


class OnionRequest : public QUrl {
    
 public:
  OnionRequest(QString& server, bool secure);
  char password[DEFIANT_REQ_REP_PASSWORD_LENGTH + 1];
  bool secure;

 private:
  char path[1024];
  
  void randomPath();

};


#endif
