#!/bin/bash

: ${DEFIANCE_PRIVATE_KEY_PATH?"Need to set DEFIANCE_PRIVATE_KEY_PATH!!"}

if [ -n  "$DEFIANCE_PRIVATE_KEY_PATH" ]
then
    echo "Using private key located at ${DEFIANCE_PRIVATE_KEY_PATH} to sign onions!" 
fi

: ${DEFIANCE_PUBLIC_KEY_PATH?"Need to set DEFIANCE_PUBLIC_KEY_PATH!!"}

if [ -n  "$DEFIANCE_PUBLIC_KEY_PATH" ]
then
    echo "Using public key located at ${DEFIANCE_PUBLIC_KEY_PATH} to verfiy signatures!" 
fi

: ${DEFIANT_ONIONFACTORY_PORT?"Need to set DEFIANT_ONIONFACTORY_PORT!!"}

: ${DEFIANT_CLASSPATH?"Need to set DEFIANT_CLASSPATH!!"}


if [ -n  "$DEFIANT_ONIONFACTORY_NET_URL" ]
then
    echo "Using ${DEFIANT_ONIONFACTORY_NET_URL} to fetch the NETs!" 
else
    echo "WARNING: DEFIANT_ONIONFACTORY_NET_URL is *not* set; your NETs will be fake!" 
fi

if [ -n  "$DEFIANT_DUMMY_CAPTCHA" ]
then
    echo "Using ${DEFIANT_DUMMY_CAPTCHA} to create captcha!" 
else
    echo "WARNING: DEFIANT_DUMMY_CAPTCHA is *not* set; your captchas wil be difficult!"
fi


bridge=127.0.0.1:8888

if [ -n "$DEFIANT_ONIONFACTORY_EMAIL" ]
then
    host=`hostname`
    echo ${host}
    /usr/bin/mail -s "onionfactory on ${host} has been restarted" ${DEFIANT_ONIONFACTORY_EMAIL} < /dev/null
fi


#restart thttpd
#just in case we are restarting as a service rather than rebooting...
/usr/bin/killall -quiet thttpd
#let the dust settle 
sleep 1
#now restart it
cd ${HOME}/OnionFactory/thttpd/htdocs/
../sbin/thttpd -p ${DEFIANT_ONIONFACTORY_PORT} -h 0.0.0.0 -l ${HOME}/OnionFactory/thttpd/log/thttpd.log -i ${HOME}/OnionFactory/thttpd/run/thttpd.pid
echo "Restarted thttpd"


#if we are configured to do so start a LOCAL tor proxy 
if [ -n "$DEFIANT_ONIONFACTORY_BRIDGE" ]
then
    #we won't kill the bridge because it is running as someone else
    /usr/bin/killall --quiet tor
    /bin/rm -f ${HOME}/OnionFactory/log/debug.log
    /bin/rm -f ${HOME}/OnionFactory/log/info.log
    #let the dust settle 
    sleep 1
    #now restart them
    cd ${HOME}/OnionFactory/log/
    /usr/sbin/tor -f ${HOME}/tor_socks.torrc Bridge $1 ${DEFIANT_ONIONFACTORY_BRIDGE} &
else
    echo "Not restarting a tor proxy because I have no bridge address"
fi










