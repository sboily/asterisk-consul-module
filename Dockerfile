from quintana/asterisk:latest

MAINTAINER Sylvain Boily <sboily@avencall.com>

# Install Asterisk consul module
WORKDIR /usr/src
ADD . /usr/src/asterisk-consul-module
WORKDIR /usr/src/asterisk-consul-module
RUN make
RUN make install
RUN make samples

WORKDIR /root
RUN rm /etc/asterisk/*
ADD res_discovery_consul.conf.sample /etc/asterisk/res_discovery_consul.conf
ADD contribs/asterisk/*.conf /etc/asterisk/
ONBUILD ADD res_discovery_consul.conf.sample /etc/asterisk/res_discovery_consul.conf

RUN rm -rf /usr/src/*
