#!/bin/bash
pulseaudio --system &> /tmp/pulse.log &
linphonec $@
