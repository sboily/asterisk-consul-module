from quintana/asterisk:latest

MAINTAINER Sylvain Boily <sboily@avencall.com>

# Install Asterisk consul module
WORKDIR /usr/src
RUN git clone https://github.com/sboily/asterisk-consul-module.git
WORKDIR /usr/src/asterisk-consul-module
RUN make
RUN make install
RUN make samples

RUN rm /etc/asterisk/*
ADD res_discovery_consul.conf.sample /etc/asterisk/res_discovery_consul.conf
ADD contribs/asterisk/*.conf /etc/asterisk/
ONBUILD ADD res_discovery_consul.conf.sample /etc/asterisk/res_discovery_consul.conf
