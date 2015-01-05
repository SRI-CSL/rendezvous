#include <QtGui>
#include <QPixmap>
#include <QtDebug>
#include <QNetworkProxy>
#include "rendezvous.h"
#include "onionmanager.h"
#include "stegospawner.h"
#include "dancer.h"
#include "util.h"
#include "defiantrequest.h"

Rendezvous::Rendezvous(QWidget *parent) : QWidget(parent){
  label = new QLabel(QApplication::translate(context, "Server:"));
  line = new QLineEdit();
  button = new QPushButton(QApplication::translate(context, "Go"));
  console = new QTextEdit();
  display = new QScrollArea();
  image = new QLabel();
  manager = new QNetworkAccessManager(this);
  proxy = NULL;
  proxycurlcode = -1;
  _useCurl = false;
  _noDancing = false;
  secure = new QCheckBox("ssl", this);
  console->setReadOnly(true);
  image->setBackgroundRole(QPalette::Base);
  image->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
  image->setScaledContents(true);
  display->setBackgroundRole(QPalette::Dark);
  onionManager = new OnionManager(this);
  QHBoxLayout *topLayout = new QHBoxLayout();
  topLayout->addWidget(label);
  topLayout->addWidget(line);
  topLayout->addWidget(button);
  topLayout->addWidget(secure);
  QVBoxLayout *mainLayout = new QVBoxLayout();
  mainLayout->addLayout(topLayout);

  progress = new QProgressBar(this);
  progress->setMinimum(0);
  progress->setMaximum(100);

  mainLayout->addWidget(progress);
  mainLayout->addWidget(display);
  mainLayout->addWidget(console);
  setLayout(mainLayout);
  resize(600, 300);
  setWindowTitle(QApplication::translate(context, "Address Discovery Client"));
  
  connect(button, SIGNAL(clicked()), this, SLOT(go())); 
  connect(line, SIGNAL(returnPressed()), this, SLOT(go()));
  connect(onionManager, SIGNAL(statusUpdate(QString, int)), this, SLOT(statusUpdate(QString, int)));
  connect(onionManager, SIGNAL(progressUpdate(int)), this, SLOT(progressUpdate(int)));

  
  envSanityCheck();
  
  proxyhostname = "";
  proxyportno = 0;

  
  Util::debug() << " Rendezvous constructing complete!";

  /* attempt to appear on the desktop */
  activateWindow();
  raise();
  show();

}


void Rendezvous::setEnabled(bool enabled){
  button->setEnabled(enabled);
  line->setEnabled(enabled);
  secure->setEnabled(enabled);
  Util::debug() << " Widgets enabled = " << enabled;
}


void Rendezvous::setLabel(QString text){
  label->setText(text);
}

void Rendezvous::setGeometry(QString text){
  if(text != NULL){
    QStringList coords = text.split("x");
    if(coords.size() == 2){
      bool wOK, hOK;
      int width = coords.at(0).toInt(&wOK, 10);
      int height = coords.at(1).toInt(&hOK, 10);
      if(wOK && hOK){
        resize(width, height);
      }
    }
  }
}

bool Rendezvous::isSecure(){
  return secure->isChecked();
}

void Rendezvous::setSecure(bool s){
  secure->setChecked(s);
}

void Rendezvous::setServer(QString server){
  line->setText(server);
}

void Rendezvous::setUseCurl(bool value){
  _useCurl = value;
}

bool Rendezvous::useCurl(){
  return _useCurl;
}

void Rendezvous::setNoDancing(){
  _noDancing = true;
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  if(env.value("IPNPORT4STEGOTORUS").isEmpty()){
    Util::debug() << " no dancing DEMANDS a value for IPNPORT4STEGOTORUS, please rectify!";
    exit(1);
  }
}

bool Rendezvous::noDancing(){
  return _noDancing;
}

void Rendezvous::setProxy(QString proxystring){
  if(proxystring != NULL){
    QStringList items = proxystring.split(":");
    if(items.size() == 2){
      bool portOK;
      proxyhostname = items.at(0);
      QString proxyportstring = items.at(1);
      proxyportno = proxyportstring.toInt(&portOK, 10);
      if(portOK){
        Util::debug() << " Proxy hostname = " << proxyhostname;
        Util::debug() << " Proxy portno   = " << proxyportno;
        if(!_useCurl){
          proxy = new QNetworkProxy();
          proxy->setType(QNetworkProxy::Socks5Proxy);
          proxy->setHostName(proxyhostname);
          proxy->setPort(proxyportno);
          manager->setProxy(*proxy);
        }
      } else {
        Util::debug() << " Bad proxy portno: " << proxyportstring;
      }
    }
  }
}

void Rendezvous::setProxyType(QString proxytype){
  if(proxytype != NULL){
    bool codeOK;
    int curlcode = proxytype.toInt(&codeOK, 10);
    if(codeOK){
      const char* protocol =  proxystring(curlcode);
      if(protocol != NULL){
        Util::debug() << " Using protocol: " << protocol;
        proxycurlcode = curlcode;
        return;
      }
    }
    //something is not right
    char* hints = proxyhints();
    Util::debug() <<  hints;
    free(hints);
  }
}

bool Rendezvous::envSanityCheck(){
  bool retval = true;
  retval = Dancer::configure();
  if(!retval){
    statusUpdate(Dancer::getStatus(), 0);
  }
  retval = Stegospawner::configure();
  if(!retval){
    statusUpdate(Stegospawner::getStatus(), 0);
  }
  return retval;
}

void Rendezvous::go(){
  onionManager->click(line->text());
  line->setFocus(Qt::OtherFocusReason);
  // Util::debug() << "Focus please!";
}



void Rendezvous::statusUpdate(QString message, int flush){
  if(flush){  console->clear(); }
  console->insertPlainText(message);
  console->append("");
}


void Rendezvous::progressUpdate(int percent){
  //fprintf(stderr, "Progress value = %d\n", percent);
  progress->setValue(percent);
}

void Rendezvous::renderImage(QByteArray& pixels){
    QPixmap pixmap;
    bool success = pixmap.loadFromData(pixels);
    if(success){
      image->setPixmap(pixmap);
      display->setWidget(image);
      display->setWidgetResizable(true);
      image->adjustSize();
    }
}

void Rendezvous::clearLine(){
  line->clear();
}

void Rendezvous::clearConsole(){
  console->clear(); 
}

QString Rendezvous::getLine(){
  return line->text();
}

void Rendezvous::clearImage(){
  QPixmap pixmap;
  image->setPixmap(pixmap);
}
