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

Docker
------

First edit the sample to have a good configuration.
To build image to test with docker.

    docker build -t asterisk-consul .
    docker run -it asterisk-consul bash
    asterisk

To play with the module

    asterisk -r
    CLI> modules unload res_discovery_consul.so
    CLI> modules load res_discovery_consul.so
