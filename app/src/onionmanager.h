#ifndef ONIONMANAGER_H
#define ONIONMANAGER_H

#include <QObject>
#include <QtNetwork>

#include "onion.h"
#include "defiantclient.h"

class Rendezvous;
class CurlThread;
class PowThread;
class PowReporter;
class Dancer;
class OnionRequest;

class OnionManager : public QObject {
  Q_OBJECT
    
    public:
  OnionManager(Rendezvous* u);


  void sendForOnion(QString server);


 signals:
  void statusUpdate(QString, int);
  void progressUpdate(int);

  public  slots:
  void click(QString msg);
  void processOnion();
  void workerFinished();
  void reporterFinished();
  void dancerUpdate(QByteArray);
  void dancerDone();
  void sslErrorHandler(QNetworkReply* qnr, const QList<QSslError> & errlist);


 private:
  void validateOnion(QByteArray& encryptedOnion);
  void doTheDirty();

  void setHeaders(QNetworkRequest&);

  void sendForOnionViaQt(QString server, OnionRequest* req);
  void sendForOnionViaCurl(OnionRequest* req);
  
  void processOnionFromQt();
  void processOnionFromCurl();
  void processOnionAux(QByteArray& encryptedOnion, int contentCode);
  
 private:
  onion_t onion;
  Rendezvous *gui;
  QNetworkAccessManager* manager;
  
  char password[DEFIANT_REQ_REP_PASSWORD_LENGTH + 1];
  
  OnionRequest* onionrequest;

  CurlThread* curler;
  PowThread* worker;
  PowReporter* reporter;
  Dancer* dancer;
 
  QByteArray dancerData;

  
  bool mood4dancing;
  bool fallBackSet;

 public:
  volatile long attempts;

};

#endif
