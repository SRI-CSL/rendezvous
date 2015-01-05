#include "onionmanager.h"
#include "rendezvous.h"
#include "util.h"
#include "onionrequest.h"       
#include "curlthread.h"
#include "powthread.h"
#include "powreporter.h"       
#include "dancer.h"
#include "stegoargs.h"
#include "stegospawner.h"
#include "outguess.h"
#include "defiantrequest.h"

OnionManager::OnionManager(Rendezvous* u){
  gui = u;
  onion = NULL;
  manager = u->getManager();
  onionrequest = NULL;
  curler = NULL;
  worker = NULL;
  reporter = NULL;
  attempts = 0;

  dancer = NULL;
  
  /* seed the random number generator */
  srand(time(NULL));

  /* clear out the password array */
  memset(password, '\0', DEFIANT_REQ_REP_PASSWORD_LENGTH + 1);

  /* check this when we fetch an onion */
  mood4dancing = true;

  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  fallBackSet =  !env.value("IPNPORT4STEGOTORUS").isEmpty();
    
}


void OnionManager::click(QString content){
  Util::debug() << " OnionManager::click " << content  << " " << gui->isSecure();
  if(onion == NULL){
    /* decide if we are in the mood to dance */
    mood4dancing = !gui->noDancing();
    Util::debug() << " !?!?!? N.B.: OnionManager() dancing = " << mood4dancing  << " fallBackSet = " <<  fallBackSet << "!?!?!?";
    sendForOnion(content);
  } else {
    int type = ONION_TYPE(onion);
    info_onion(stderr, onion);
    switch(type){
    case POW: {
      if(worker == NULL){
        emit statusUpdate("This layer is a Proof-Of-Work Onion", 1); 
        emit statusUpdate("Be patient while we search for a solution to the puzzle!", 0);
        gui->setEnabled(false);
        attempts = 0;
        worker = new PowThread(this, onion);
        reporter = new PowReporter(this);
        connect(worker, SIGNAL(finished()), this, SLOT(workerFinished()));
        connect(reporter, SIGNAL(finished()), this, SLOT(reporterFinished()));
        connect(worker, SIGNAL(finished()), reporter, SLOT(workerFinished()));
        /*  MYSTERY: no idea why the (QObject*) cast is necessary? */
        connect(reporter, SIGNAL(progressUpdate(int)), (QObject*)gui, SLOT(progressUpdate(int)));
        worker->start();
        reporter->start();
      } else {
        emit statusUpdate("Patience grasshopper...", 0); 
      }
      break;
    }
    case CAPTCHA: {
      QString secret = gui->getLine();
      if(secret.isEmpty()){
        QByteArray pixels;
        pixels.append(ONION_PUZZLE(onion), ONION_PUZZLE_SIZE(onion));
        gui->renderImage(pixels);
        gui->setLabel("Password:");
        emit statusUpdate("The inner onion is a captcha, type the password and press \"go\" again!", 1);
      } else {
        onion_t inner = NULL;
        int defcode = peel_captcha_onion(secret.toAscii().data(), onion, &inner);
        if(defcode == DEFIANT_OK){
          free(onion);
          onion = inner;
          gui->clearLine();
          gui->setLabel("");
          emit statusUpdate("Excellent another layer gone, press \"go\" to peel the next one!", 1);
        } else {
          Util::debug() << " peel_captcha_onion returned " << defcode ;
          emit statusUpdate("Nope, wanna try again ...", 0);
        }
      }
      break;
    }
    case BASE: {
      //disabling the button
      gui->setEnabled(false);
      if(mood4dancing){
        if(dancer == NULL){
          QString nep = QString((char*)ONION_DATA(onion));
          emit gui->statusUpdate("Excellent we have a nep, now commencing ACS dance!", 1);
          Util::debug() << nep;
          dancer = new Dancer(nep);
          connect(dancer, SIGNAL(dancerUpdate(QByteArray)), this, SLOT(dancerUpdate(QByteArray)));
          connect(dancer, SIGNAL(finished()), this, SLOT(dancerDone()));
          dancer->start();
        } else {
          emit statusUpdate("Patience grasshopper...", 0); 
        }
      } else {
        Util::debug() << "not dancing; stegosoaring";
        doTheDirty();
      }
      break;
    }
    default:
      emit statusUpdate("UNKNOWN!", 0); break;
    }
  }
}

void OnionManager::dancerUpdate(QByteArray update){
  Util::debug() << "dancerUpdate: " << update;
  emit statusUpdate(QString(update), 0); 
}

void OnionManager::dancerDone(){
  //FIXME: bit of a hack here; not sure why this gets executed twice?
  if(dancer != NULL){
    Dancer* _dancer = dancer;
    dancer = NULL;
    emit statusUpdate("The dance is done, the parsing remains...", 0); 
    Util::debug() << "dancer done dancing";
    dancerData.append(_dancer->getData());
    Util::debug() << "deleting dancer";
    delete _dancer;
    doTheDirty();
  }
}

void OnionManager::doTheDirty(){
  QByteArray localaddr("127.0.0.1:1080");
  StegoArgs args(dancerData, localaddr);
  Util::debug() << "Parsing stegoargs = " << args.toString();
  if(!mood4dancing || fallBackSet || args.isOK()){
    emit statusUpdate("The parsing went wonderfully: ", 1);
    emit statusUpdate(args.toString(), 0);
    emit statusUpdate("Spawning stegotorus next...", 0);
    bool retval = Stegospawner::spawnStegotorus(args);
    if(retval){
      emit statusUpdate("Spawning SUCCESS!", 0);
    } else {
      emit statusUpdate("Spawning failed", 0);
      gui->setEnabled(true);
    }
  } else {
    emit statusUpdate("The parsing failed, all that effort for naught. Sorry :-(", 1);
    gui->setEnabled(true);
  }
}

void OnionManager::reporterFinished(){
  if(reporter != NULL){
    Util::debug() << "deleteing reporter";
    delete reporter;
    reporter = NULL;
  }
}

void OnionManager::workerFinished(){
  if(worker != NULL){
    onion_t inner = worker->inner;
    if(inner != NULL){
      emit progressUpdate(100);
      emit statusUpdate("Bingo, we solved the puzzle, removing yet another layer, press go to see what's next!", 1);
      free(onion);
      onion = inner;
      Util::debug() << "deleteing worker";
      delete worker;
      worker = NULL;
    } else {
      emit statusUpdate("POW failure :-(", 0);
    }
    gui->setEnabled(true);
  }
}

void OnionManager::sslErrorHandler(QNetworkReply* reply, const QList<QSslError> & errlist){
  Util::debug() << " sslErrorHandler IGNORING the following errors: ";
  // show list of all ssl errors
  foreach (QSslError err, errlist) {
    Util::debug() << " \tssl error: " << err;
  }
  reply->ignoreSslErrors();
}

void OnionManager::sendForOnionViaQt(QString server, OnionRequest* req){
  QNetworkRequest request;
  Util::debug() << " sendForOnion constructing request to " << server ;
  if(req->secure){
    Util::debug() << " setting QSslConfiguration";
    request.setSslConfiguration( QSslConfiguration::defaultConfiguration() );
  }
  //set the url
  request.setUrl(*req);
  //make sure it looks like a real browser request
  setHeaders(request);
  Util::debug() << " sending request to " << server ;
  QNetworkReply *reply = manager->get(request);
  connect(manager, SIGNAL(sslErrors(QNetworkReply*, const QList<QSslError> & )),
          this, SLOT(sslErrorHandler(QNetworkReply*, const QList<QSslError> & )));
  Util::debug() << " sent request to " << server ;
  connect(reply, SIGNAL(finished()), this, SLOT(processOnion()));
}


void OnionManager::sendForOnionViaCurl(OnionRequest* req){
  curler = new CurlThread(gui, this, req);
  connect(curler, SIGNAL(finished()), this, SLOT(processOnion()));
  curler->start();
}


void OnionManager::sendForOnion(QString server){
  bool secure = gui->isSecure();
  if(server.isEmpty()){
    emit statusUpdate("Need to enter the apache server's url!", 1);
  } else {
    onionrequest = new OnionRequest(server, secure);
    if(onionrequest != NULL){
      //disabling the button
      gui->setEnabled(false);
      //remember the password for dealing with the reply
      memcpy(password, onionrequest->password, DEFIANT_REQ_REP_PASSWORD_LENGTH + 1); 
      if(gui->useCurl()){
        sendForOnionViaCurl(onionrequest);
      } else {
        sendForOnionViaQt(server, onionrequest);
      }
      emit statusUpdate(QString("Sending onion request to ").append(server), 0);
    } else {
      Util::debug() << " sendForOnion: request did not construct for " << server  << "!";
    }
  }
}

void OnionManager::validateOnion(QByteArray& encryptedOnion){
  Util::debug() << "processOnion: encryptedOnion has length " << encryptedOnion.size();
  int onion_sz = 0;
  int errcode = DEFIANT_OK; 
  onion = (onion_t)defiant_pwd_decrypt(password, (const uchar*)encryptedOnion.data(), encryptedOnion.size(), &onion_sz); 
  if (onion == NULL) {
    Util::debug() << "Decrypting onion failed: No onion";
  } else if (onion_sz < (int)sizeof(onion_header_t)) {
    Util::debug() << "Decrypting onion failed: onion_sz less than onion header";
  } else if (!ONION_IS_ONION(onion)) {
    Util::debug() << "Decrypting onion failed: Onion Magic Incorrect";
  } else if (onion_sz != (int)ONION_SIZE(onion)) {
    Util::debug() << "Decrypting onion failed: onion_sz (" <<
		onion_sz << ") does nat match real onion size (" <<
		(int)ONION_SIZE(onion) << ", " <<
		(int)ONION_DATA_SIZE(onion) << " + " <<
		(int)ONION_PUZZLE_SIZE(onion) << " )";
  } else {
    errcode = verify_onion(onion);
    if(errcode == DEFIANT_OK){
      onion_t inner_onion = NULL;
      emit statusUpdate("The server returned an onion whose signature we VERIFIED!", 0);
      errcode = peel_signed_onion(onion, &inner_onion);
      if(errcode == DEFIANT_OK){
        free(onion);
        onion = inner_onion;
        gui->clearLine();
        gui->setLabel("");
        emit statusUpdate("The verified onion peeled just fine, press \"go\" to peel the next layer!", 0);
      } else {
        emit statusUpdate("Peeling it went wrong, very odd.", 0);
      }
    } else {
      emit statusUpdate("The server returned an onion whose signature we COULD NOT verify -- try again?", 0);
      free(onion);
      onion = NULL;
    }
  }
}

void OnionManager::processOnionAux(QByteArray& encryptedOnion, int contentCode){
  Util::debug() << "processOnionAux:  contentCode = " << contentCode << " password = " << password << " of length " << strlen(password);
  if(contentCode == DEFIANT_CONTENT_TYPE_JPEG){
    //should be a stegged image
    //Could for fun display the image:
    gui->renderImage(encryptedOnion);

    char* onion = NULL;
    size_t onion_sz = 0;
    int errcode = extract2(password, encryptedOnion.constData(), encryptedOnion.size(),  &onion, &onion_sz);
    if(errcode != DEFIANT_OK){
      Util::debug() << "processOnion: extract returned error code: " << errcode;
    } else {
      QByteArray steggedOnion(onion, onion_sz);
      validateOnion(steggedOnion);
    }
    free(onion);
  } else if(contentCode == DEFIANT_CONTENT_TYPE_GIF){
    //should be a raw onion
    validateOnion(encryptedOnion);
  } else {
    Util::debug() << "processOnion: unexpected content type: " << contentCode ;
  }
}

void OnionManager::processOnionFromQt(){
  QNetworkReply* reply = qobject_cast<QNetworkReply*>(const_cast<QObject*>(sender()));
  Util::debug() << "processOnion: got reply to request for " << reply->request().url().toString() ;
  if (reply->error() == QNetworkReply::NoError) {
    QVariant status_attr = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    /*
    Util::debug() << "processOnion: reply result:                " << reply->error();
    Util::debug() << "processOnion: reply has content type:      " << reply->header(QNetworkRequest::ContentTypeHeader).toString();
    Util::debug() << "processOnion: reply has content length:    " << reply->header(QNetworkRequest::ContentLengthHeader).toString();
    //unsolved mystery: why is the content length missing? perl finds it just fine, so does wire shark. 
    QList<QByteArray> list  = reply->rawHeaderList();
    for (int i = 0; i < list.size(); ++i) {  Util::debug() << list.at(i) ;   }
    */
    if (status_attr.isValid() && (status_attr.toInt() == 200)){
      Util::debug() << "processOnion: status_attr.isValid() && (status_attr.toInt() == 200)";
      int contentCode; 
      QString contentType = reply->header(QNetworkRequest::ContentTypeHeader).toString();
      if(contentType == "image/jpeg"){
        contentCode = DEFIANT_CONTENT_TYPE_JPEG;
      } else  if(contentType == "image/gif"){
        contentCode = DEFIANT_CONTENT_TYPE_GIF;
      } else {
        contentCode = DEFIANT_CONTENT_TYPE_UNKNOWN;
      }
      QByteArray encryptedOnion = reply->readAll();
      processOnionAux(encryptedOnion, contentCode);
    } else {
      Util::debug() << "processOnion: !status_attr.isValid() || (status_attr.toInt() != 200)";
    }
  } else {
    emit  statusUpdate(QString("The request to that url was unhappy: ").append(reply->errorString()), 1);
    Util::debug() << "processOnion: reply result had an error (BAD): " << reply->error();
  }
}

void OnionManager::processOnionFromCurl(){
      Util::debug() << "processOnionFromCurl: reply received ";
      CurlThread* reply = qobject_cast<CurlThread*>(const_cast<QObject*>(sender()));
      Util::debug() << "processOnionFromCurl: got reply to request for   " << reply->request->toString() ;
      Util::debug() << "                                bytes received = " << reply->data_size ;
      QByteArray encryptedOnion(reply->data, reply->data_size);
      processOnionAux(encryptedOnion, reply->data_type);
}

void OnionManager::processOnion(){
  if(gui->useCurl()){
    processOnionFromCurl();
  } else {
    processOnionFromQt();
  }
  gui->setEnabled(true);
}




//Connection: keep-alive
//User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.79 Safari/537.4
//Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
//Accept-Encoding: gzip,deflate,sdch
//Accept-Language: en-US,en;q=0.8
//Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n

//image/png,image/*;q=0.8,*/*;q=0.5

void OnionManager::setHeaders(QNetworkRequest& request){
  request.setRawHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.79 Safari/537.4");
  request.setRawHeader("Accept", "image/png,image/*;q=0.8,*/*;q=0.5");
  //DOES NOT LIKE: request.setRawHeader("Accept-Encoding", "gzip");
  //request.setRawHeader("Accept-Language", "en-US,en;q=0.8");  
  //request.setRawHeader("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.3");

}


