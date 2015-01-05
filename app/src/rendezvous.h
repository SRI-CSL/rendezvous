#ifndef RENDEZVOUS_H
#define RENDEZVOUS_H

#include <QtGui>
#include <QWidget>
#include <QtNetwork>
#include <QCheckBox>

#include "onionmanager.h"

static const char context[] = "client";

class Rendezvous : public QWidget {
  Q_OBJECT

    public:
  Rendezvous(QWidget *parent = 0);
  void renderImage(QByteArray& pixels);
  void clearLine();
  QString getLine();
  void clearConsole();
  void clearImage();
  QNetworkAccessManager* getManager(){ return manager; };

  void setEnabled(bool);

  void setServer(QString);
  void setSecure(bool);
  void setProxy(QString);
  void setProxyType(QString);
  void setGeometry(QString);
  void setLabel(QString);
  void setUseCurl(bool);
  void setNoDancing();

  bool isSecure();
  bool useCurl();
  bool noDancing();
 


  bool envSanityCheck();


  QString dirStegotorus;
  QString exeStegotorus;
  QString ipNport4Stegotorus;

  public slots:
  void go();
  void statusUpdate(QString message, int flush);
  void progressUpdate(int percent);

 public:
  QString proxyhostname;
  quint16 proxyportno;
  int proxycurlcode;
  
 private:
  QLabel       *label;
  QLineEdit    *line;
  QPushButton  *button;
  QTextEdit    *console;
  QScrollArea  *display; 
  QLabel       *image;
  QProgressBar *progress;
  QCheckBox    *secure;

  QNetworkAccessManager *manager;

  OnionManager *onionManager;

  QNetworkProxy *proxy;

  bool _useCurl;

  bool _noDancing;


 };

 #endif
