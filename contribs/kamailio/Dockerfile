from debian:jessie

MAINTAINER Sylvain Boily "sboily@avencall.com"

RUN echo "deb http://deb.kamailio.org/kamailio jessie main" > /etc/apt/sources.list.d/kamailio.list
RUN apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xfb40d3e6508ea4c8
RUN apt-get -yqq update \
    && apt-get -yqq install kamailio

ENV VERSION 0.10.0

WORKDIR /usr/src
ADD https://github.com/hashicorp/consul-template/releases/download/v${VERSION}/consul-template_${VERSION}_linux_amd64.tar.gz /usr/src/
RUN tar xfvz consul-template_${VERSION}_linux_amd64.tar.gz
RUN mv consul-template_${VERSION}_linux_amd64/consul-template /usr/bin

ADD ./config/kamailio/* /etc/kamailio/
ADD ./config/consul-template/* /config/

EXPOSE 5060/udp

CMD consul-template -log-level debug -config /config/template.hcl
