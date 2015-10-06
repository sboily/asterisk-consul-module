from debian:jessie

MAINTAINER Sylvain Boily "sboily@avencall.com"

RUN echo "deb http://deb.kamailio.org/kamailio jessie main" > /etc/apt/sources.list.d/kamailio.list
RUN apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xfb40d3e6508ea4c8
RUN apt-get -yqq update \
    && apt-get -yqq install kamailio

ADD config/* /etc/kamailio/

EXPOSE 5060/udp

CMD kamailio -ddDDe
