#include <QtGui>

#include "stegoargs.h"
#include "util.h"

static bool debug = false;

StegoArgs::StegoArgs(QByteArray& dancerData, QByteArray& laddr){
  OK = false;
  localaddr.append(laddr);
  QList<QByteArray> lines = dancerData.split('\n');
  if(debug){ Util::debug() << "dancer data parses to " << lines.size() << " lines long"; }
  for(int i = 0; i < lines.size(); i++){
    QByteArray line = lines.at(i);
    if(debug){ Util::debug() << "lines[" << i << "] = " << line; }
    if(line.isEmpty() || line.startsWith("STATUS:")){
      if(debug){ Util::debug() << "continuing"; }
      continue;
    } 
    if(line.startsWith("HOST:")){ host.append(chomp(line)); continue; }
    if(line.startsWith("PROTOCOL:")){ protocol.append(chomp(line)); continue; }
    if(line.startsWith("PORT:")){ port.append(chomp(line)); continue; }
    if(line.startsWith("IDENTITY:")){ identity.append(chomp(line)); continue; }
    if(line.startsWith("SECRET:")){ secret.append(chomp(line)); continue; }
    if(line.startsWith("EXPIRATION:")){ expiration.append(chomp(line)); continue; }
    if(line.startsWith("METHOD:")){ method.append(chomp(line)); continue; }
    if(line.startsWith("SCHEME:")){ scheme.append(chomp(line)); continue; }
  }
  OK = !(localaddr.isEmpty() || host.isEmpty() || port.isEmpty());
}

bool StegoArgs::isOK(){
  return OK;
}

QString StegoArgs::toString(){
  QString retval;
  retval.append("localaddr=").append(localaddr).append(" ");//.append("\n");
  retval.append("host=").append(host).append(" ");//.append("\n");
  //  retval.append("protocol=").append(protocol).append("\n");
  retval.append("port=").append(port).append(" ");//.append("\n");
  //  retval.append("identity=").append(identity).append("\n");
  //  retval.append("secret=").append(secret).append("\n");
  //  retval.append("expiration=").append(expiration).append("\n");
  //  retval.append("method=").append(method).append("\n");
  //  retval.append("scheme=").append(scheme).append("\n");
  return retval;
}


QByteArray StegoArgs::chomp(QByteArray& line){
  int start = line.indexOf(':');
  return line.mid(start + 1).trimmed();
}
