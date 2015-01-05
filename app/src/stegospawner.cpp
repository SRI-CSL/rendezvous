#include <QtGui>
#include <QProcessEnvironment>

#include "stegospawner.h"
#include "util.h"



static QString stegologfile = "/tmp/stegotorus.log";

bool Stegospawner::debug = false;

QFileInfo  Stegospawner::stegotorus;
QDir Stegospawner::directory = QDir("");;

QString Stegospawner::status = "";
QString Stegospawner::dirStegotorus = "";
QString Stegospawner::exeStegotorus = "";
QString Stegospawner::ipNport4Stegotorus = "";


bool Stegospawner::configure(){
  bool retval = true;
  status.clear();
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  if(ipNport4Stegotorus.isEmpty()){
    ipNport4Stegotorus = env.value("IPNPORT4STEGOTORUS");
  }
  if(dirStegotorus.isEmpty()){
    dirStegotorus = env.value("DIRSTEGOTORUS");
  }
  if(exeStegotorus.isEmpty()){
    exeStegotorus = env.value("EXESTEGOTORUS");
  }
  if(dirStegotorus.isEmpty()){
    status.append("DIRSTEGOTORUS not set, should be the directory containing the stegexe!\n");
    retval = false;
  }
  if(exeStegotorus.isEmpty()){
    status.append("EXESTEGOTORUS not set, should be the name of the steg executable!\n");
    retval = false;
  }
  //if we are OK we should check to see if the puppy is there, and make the path
  if(retval){
    directory  = QDir(dirStegotorus);
    stegotorus = QFileInfo(directory, exeStegotorus);
    if(!stegotorus.exists()){
      Util::debug() << " Stegospawner can't find" << stegotorus.absoluteFilePath();
      status.append("Sorry, but I can't seem to find: \n\n\t");
      status.append(stegotorus.absoluteFilePath());
      status.append("\n\nCan you?\n");
      retval = false;
    }
  }
  return retval;
}


bool Stegospawner::spawnStegotorus(QString host, QString port, QString localaddr){
  //./stegotorus --log-min-severity=warn chop socks 127.0.0.1:1080 127.0.0.1:8080 http 127.0.0.1:8081 http
  //./stegotorus --log-min-severity=warn chop socks 127.0.0.1:1080 [IPNPORT4STEGOTORUS COVER]^4
  //./stegotorus --log-min-severity=warn chop socks 127.0.0.1:SOCKS_LISTEN_PORT [SERVER_ADDR:PORT COVER]^4
  //in my /opt/local/etc/tor/torrc you see: Socks4Proxy 127.0.0.1:1080
  bool retval = false;
  status.clear();
  bool envOK = configure();
  if(!envOK){ return retval;  }
  QStringList arguments;
  QString ipNport;
  ipNport.append(host).append(':').append(port);
  // allow for the possibility of a cheat due to adverse network conditions during a demo...
  // in which case ipNport4Stegotorus is likely to be "127.0.0.1:8080"
  QString params = ipNport4Stegotorus.isEmpty() ? ipNport : ipNport4Stegotorus;
  if(debug){
    arguments << "--log-min-severity=warn" << "chop" << "socks"  << "--trace-packets"  << localaddr
              << params << "http" << params << "http"
              << params << "http" << params << "http";
  } else {
    arguments << "--log-min-severity=warn" << "chop" << "socks"  << localaddr
              << params << "http" << params << "http"
              << params << "http" << params << "http";
  }
  //some yada yada which will eventually go away, probably ...
  if(false && debug){
    QString execvp = stegotorus.absoluteFilePath();
    execvp.append(" ");
    for(int j = 0; j < arguments.size(); j++){
      execvp.append(arguments.at(j)).append(" ");
    }
    status.append(QString("Forking off ").append(execvp).append(" in directory ").append(directory.path()));
  }

  if(debug){
    QProcess* stegoprocess = new QProcess();
    stegoprocess->setStandardOutputFile(stegologfile);
    stegoprocess->setStandardErrorFile(stegologfile);
    stegoprocess->setWorkingDirectory(directory.path());
    retval = true;
    stegoprocess->start(stegotorus.absoluteFilePath(), arguments);
    Util::debug() <<  " QProcess::start: "  << stegotorus.absoluteFilePath() << arguments;
    Util::debug() <<  " QProcess::start NOT DETACHED!" << retval;
  } else {
    retval = QProcess::startDetached(stegotorus.absoluteFilePath(), arguments, directory.path());
    Util::debug() <<  " QProcess::startDetached: "  << stegotorus.absoluteFilePath() << arguments;
    Util::debug() <<  " QProcess::startDetached returned " << retval;
  }
  return retval;
}

bool Stegospawner::spawnStegotorus(StegoArgs& args){
  QString host = args.host;
  QString port = args.port;
  QString localaddr  = args.localaddr;
  return Stegospawner::spawnStegotorus(host, port, localaddr);
}


QString Stegospawner::getStatus(){
  return status;
}

