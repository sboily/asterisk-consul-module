Consul discovery module for Asterisk
====================================

This provides a discovery consul resource for Asterisk, which allows you to use
the a discovery service like consul with Asterisk. This module use the consul REST API.
It works with asterisk versions 13.x or later

Requirements
------------
- Asterisk 13.x (or later) header files
- LibCurl (or later) libraries and header files

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

If you want to enable the http check, to need to enable the http interface, and it need to be accessible by consul.

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


Docker
------

First edit the sample to have a good configuration.
To build image to test with docker.

    docker build -t asterisk-consul .
    docker run -it asterisk-consul bash
    asterisk

docker-compose
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
