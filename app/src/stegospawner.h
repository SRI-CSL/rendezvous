#ifndef STEGOSPAWNER_H
#define STEGOSPAWNER_H

#include <QDir>
#include "stegoargs.h"

class Stegospawner {
  
 public:
  static bool configure();
  static bool spawnStegotorus(StegoArgs& args);
  static bool spawnStegotorus(QString host, QString port, QString localaddr);
  static QString getStatus();

  static bool debug;

 private:
  

  static QString status;

  static QFileInfo stegotorus;
  static QDir directory;

  static QString dirStegotorus;
  static QString exeStegotorus;
  static QString ipNport4Stegotorus;


};

 #endif
