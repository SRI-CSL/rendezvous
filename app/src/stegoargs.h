#ifndef STEGOARGS_H
#define STEGOARGS_H

#include <QDir>

class StegoArgs {

  friend class Stegospawner;
  
 public:
  StegoArgs(QByteArray& dancerdata, QByteArray& localaddr);

  QString toString();
  bool isOK();

 private:
  bool OK;
  QByteArray host;
  QByteArray protocol;
  QByteArray port;
  QByteArray identity;
  QByteArray secret;
  QByteArray expiration;
  QByteArray method;
  QByteArray scheme;

  QByteArray localaddr;

  QByteArray chomp(QByteArray& line);

};

 #endif
