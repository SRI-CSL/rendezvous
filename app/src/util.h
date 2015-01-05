#ifndef UTIL_H
#define UTIL_H

#include <QString>
#include <QDebug>
#include <QTime>

class Util {
  
 public:
  inline static QDebug debug(){ QDebug foo = qDebug(); foo << QTime::currentTime().toString("mm:ss.zzz"); return foo; }
  
};

#endif
