#include "rendezvous.h"
#include "onionmanager.h"
#include "onionrequest.h"
#include "curlthread.h"
#include "util.h"
#include "defiantclient.h"
#include "defiantrequest.h"




void CurlThread::run(){
  Util::debug() << " CurlThread  started.";
  QByteArray burl = request->toString().toAscii();
  QByteArray bproxyname = gui->proxyhostname.toAscii();
  error_code = send_request(burl.constData(),  gui->isSecure(), bproxyname.constData(), gui->proxyportno, gui->proxycurlcode, &data, &data_size, &data_type);
  Util::debug() << " CurlThread finished.";
}


