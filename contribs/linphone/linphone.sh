#!/bin/bash

pulseaudio --system &> /tmp/pulse.log &
echo "Init linphone daemon"
linphonecsh init -a -d6 -S -l /tmp/linphone.log
sleep 1
echo "Register linphone daemon"
linphonecsh register --host asterisk --username sylvain --password sylvain

while true
do
    echo "Telecom is fun..."
    sleep 30
done
