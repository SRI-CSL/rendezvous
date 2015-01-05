#ifndef DANCER_H
#define DANCER_H

#include <QThread>
#include <QTemporaryFile>
#include <QFileInfo>

class Dancer : public QThread {
  Q_OBJECT
    
    public:
  Dancer(QString nep);
  
  void run();

  QByteArray getData();

  static bool configure();
  static QString getStatus();



 signals:
  void dancerUpdate(QByteArray);



 private:
  
  QTemporaryFile file;
  QString nep;
  QByteArray data;

  
  static QString status;
  static QString dancerexepath;
  static QFileInfo dancerexe;


};

 #endif
