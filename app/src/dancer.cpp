#include <QtGui>


#include "rendezvous.h"
#include "dancer.h"
#include "util.h"


//static QString dancer_executable = "/Users/iam/Repositories/isc/addresspools/src/acs-dancer";
//static QString nep_file = "/Users/iam/Repositories/isc/rendezvous/app/nep.txt";


QString Dancer::status = "";
QString Dancer::dancerexepath = "";
QFileInfo Dancer::dancerexe;


bool Dancer::configure(){
  bool retval = true;
  status.clear();
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  if(dancerexepath.isEmpty()){
    dancerexepath = env.value("ISCDANCEREXE");
  }
  if(dancerexepath.isEmpty()){
    status.append("ISCDANCEREXE not set, should be the location of the ISC dancer (i.e. acs-dancer)!\n");
    retval = false;
  }
  //if we are OK we should check to see if the puppy is there, and make the path
  if(retval){
    dancerexe = QFileInfo(dancerexepath);
    if(!dancerexe.exists()){
      Util::debug() << " Dancer can't find" << dancerexe.absoluteFilePath();
      status.append("Sorry, but I can't seem to find: \n\n\t");
      status.append(dancerexe.absoluteFilePath());
      status.append("\n\nCan you?\n");
      retval = false;
    }
  }
  return retval;
}

QString Dancer::getStatus(){
  return status;
}


/*
so the ACS dance gives me:

STATUS: Performing Initial (192.0.2.101:80)
STATUS: Wait/Window - Sleeping for 17 seconds
STATUS: Performing Redirect (192.0.2.51:80)
STATUS: Address Change Signaling Dance complete
HOST: 192.0.2.99
PROTOCOL: 6
PORT: 80
IDENTITY: 23aa107b62
SECRET: f89900ffd8
EXPIRATION: 1000
METHOD: steg
SCHEME: http
STATUS: DONE (0)

and stegotorus wants:

PATH/stegotorus chop socks --server-key=KEY \
  SOCKS_LISTEN_ADDR:PORT \
  SERVER_ADDR:PORT COVER \
  SERVER_ADDR:PORT COVER \
  ...

so I can figure out  "SERVER_ADDR:PORT COVER", like so:

  192.0.2.99:80 http
  HOST:PORT SCHEME


  the big question is what is the key? 
  
*/

Dancer::Dancer(QString  n){
  nep = n;
}



void Dancer::run(){


  Util::debug() << "dancer running" ;

  if (file.open()) {
    QTextStream out(&file);
    out << nep << "\n";
    Util::debug() << file.fileName();
  }
    
  QStringList dancer_args;
  
  //  if(1){
  //    dancer_args << nep_file;
  //  } else {
  dancer_args << file.fileName();
  //  }

  Util::debug() << "dancer forking using " << dancer_args;
    
  QProcess *dancer_process = new QProcess();
    
  dancer_process->start(dancerexe.absoluteFilePath(), dancer_args);
  
  if(!dancer_process->waitForStarted()){
    Util::debug() << "dancer failed to start" ;
    return;
  } else {
    Util::debug() << "dancer forked" ;
  }
  
  Q_PID pid = dancer_process->pid();
  
  Util::debug() << "dancer pid = " << pid ;
    
  while(dancer_process->waitForReadyRead(-1)){
    QByteArray output = dancer_process->readAllStandardOutput();
    Util::debug() <<  output;
    emit dancerUpdate(output);
    data.append(output);
  }
    
  //Util::debug() << data;

  emit finished();
  
  
}

QByteArray Dancer::getData(){
  return data;
}
