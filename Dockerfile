from quintana/asterisk:latest

MAINTAINER Sylvain Boily <sboily@avencall.com>

RUN apt-get -y install librabbitmq-dev

# Install Asterisk consul module
WORKDIR /usr/src
ADD . /usr/src/asterisk-consul-module
WORKDIR /usr/src/asterisk-consul-module
RUN make
RUN make install
RUN make samples

# Install AMQP module
WORKDIR /usr/src
run git clone https://github.com/wazo-platform/wazo-res-amqp
WORKDIR /usr/src/wazo-res-amqp
RUN make
RUN make install
RUN make samples

# Install AMQP stasis module
WORKDIR /usr/src
run git clone https://github.com/wazo-platform/wazo-res-stasis-amqp
WORKDIR /usr/src/wazo-res-stasis-amqp
RUN CFLAGS="-I/usr/src/wazo-res-amqp" make
RUN make install
RUN make samples

WORKDIR /root
RUN rm /etc/asterisk/*
ADD res_discovery_consul.conf.sample /etc/asterisk/res_discovery_consul.conf
ADD contribs/asterisk/*.conf /etc/asterisk/
RUN cp /usr/src/wazo-res-amqp/amqp.conf.sample /etc/asterisk/amqp.conf
RUN cp /usr/src/wazo-res-stasis-amqp/stasis_amqp.conf.sample /etc/asterisk/stasis_amqp.conf
ONBUILD ADD res_discovery_consul.conf.sample /etc/asterisk/res_discovery_consul.conf

RUN rm -rf /usr/src/*
