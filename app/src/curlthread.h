#ifndef CURLTHREAD_H
#define CURLTHREAD_H

#include <QThread>
#include "defianterrors.h"

class OnionManager;
class OnionRequest;
class Rendezvous;

class CurlThread : public QThread {
  Q_OBJECT

 public:

  CurlThread(Rendezvous* u, OnionManager*  om, OnionRequest* req){
    manager = om;
    request = req;
    gui = u;
    error_code = DEFIANT_OK;
    data_size = 0;
    data = NULL;
    data_type = 0; 
    
  }
  
 public:
  void run();
  
 public:
  int error_code;
  size_t data_size;
  char* data;
  int data_type;

  OnionRequest* request;
  
  
 private:
  OnionManager* manager;
  Rendezvous* gui; 

};




#endif
