from haproxy
MAINTAINER Sylvain Boily "sboily@avencall.com"

ENV VERSION 0.10.0

RUN apt-get -yqq update \
    && apt-get -yqq install procps

WORKDIR /usr/src
ADD https://github.com/hashicorp/consul-template/releases/download/v${VERSION}/consul-template_${VERSION}_linux_amd64.tar.gz /usr/src/
RUN tar xfvz consul-template_${VERSION}_linux_amd64.tar.gz
RUN mv consul-template_${VERSION}_linux_amd64/consul-template /usr/bin

RUN rm -rf consul-template*

RUN mkdir /var/run/haproxy/
RUN touch /var/run/haproxy/haproxy.pid

ADD ./config /config
ONBUILD ADD ./config /config

CMD consul-template -log-level debug -config /config/template.hcl
