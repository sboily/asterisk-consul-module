Consul discovery module for Asterisk
====================================

This provides a discovery consul resource for Asterisk, which allows you to use
the a discovery service like consul with Asterisk. This module use the consul REST API.
It works with asterisk versions 13.x or later

Requirements
------------
- Asterisk 13.x (or later) header files (http://asterisk.org)
- LibCurl (or later) libraries and header files (http://curl.haxx.se/libcurl/)
- Consul (http://consul.io)

Installation
------------
    $ make
    $ make install

To install the sample configuration file, issue the following command after
the 'make install' command:

    $ make samples

Configuration
-------------

Read the config sample.

If you want to enable the http check, to need to enable the http interface on Asterisk (http.conf) and it need to be accessible by consul.

To use
------

Loading module

    asterisk -r
    CLI> modules unload res_discovery_consul.so
    CLI> modules load res_discovery_consul.so

Show settings on CLI

    asterisk -r
    CLI> discovery show settings

To enable or disable maintenance mode

    asterisk -r
    CLI> discovery set maintenance on
    CLI> discovery set maintenance off

Roadmap
-------

- API consul via https
- Support for consul KV, if you want to add specific information
- Support TTL check from consul (https://consul.io/docs/agent/checks.html)
- Disable or enable check via CLI
- Fire an event on register/deregister (https://consul.io/docs/agent/http/event.html)
- Test
- Action and Event via AMI

Docker
------

Edit the sample to have the good configuration.
To build image to test with docker.

    docker build -t asterisk-consul .
    docker run -it asterisk-consul bash
    asterisk

UDP issue
---------

If you have UDP issue run this command.

    docker run --net=host --privileged --rm cap10morgan/conntrack -D -p udp

Docker-compose
--------------

    docker-compose build --no-cache
    docker-compose up -d
    docker-compose scale asterisk=5

HA webi (xivo/xivo)

    http://your_ip:1936/

Consul webi (token: the_one_ring)

    http://your_ip:8500/ui

ARI interface (xivo/xivo)

    http://your_ip:8888/ari

Schema
------

![Asterisk Consul screenshot](/contribs/images/asterisk-consul.png?raw=true "Asterisk Consul")
![Asterisk Consul Kamailio screenshot](/contribs/images/asterisk-consul-kamailio.png?raw=true "Asterisk Consul Kamailio")
