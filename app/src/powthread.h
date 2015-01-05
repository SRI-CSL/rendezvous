#ifndef POWTHREAD_H
#define POWTHREAD_H

#include <QThread>

#include "onion.h"

class OnionManager;

class PowThread : public QThread {
  Q_OBJECT

 public:

  PowThread(OnionManager* om, onion_t o) {
    onion = o;
    manager = om;
    inner = NULL;
  }

  ~PowThread(){   }

 signals:
  void progressUpdate(int);
  
 public:
  void run();

  onion_t onion;
  onion_t inner;
  OnionManager* manager;


};




#endif
