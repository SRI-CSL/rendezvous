#ifndef POWREPORTER_H
#define POWREPORTER_H

#include <QThread>

class OnionManager;

class PowReporter : public QThread {
  Q_OBJECT

 public:

  PowReporter(OnionManager*  om){
    manager = om;
    quit = false;
  }
 
  int attempts2percent();

 signals:
  void progressUpdate(int);
  
 public:
  void run();

 public slots:
  void workerFinished();

 private:
  static long maxAttempts;
  OnionManager* manager;
  volatile bool quit;


};




#endif
