Consul discovery module for Asterisk
====================================

This provides a discovery consul resource for Asterisk, which allows you to use
a discovery service like Consul with Asterisk. This module uses the Consul REST API.
It works with Asterisk versions 13.x or later.

Requirements
------------
- Asterisk 13.x (or later) header files (http://asterisk.org)
- LibCurl (or later) libraries and header files (http://curl.haxx.se/libcurl/)
- Consul (http://consul.io)
- Asterisk development headers for the HTTP API (`asterisk/http.h`) if building from source against a non-standard Asterisk install.

Installation
------------
    $ make
    $ make install

To install the sample configuration file, issue the following command after
the 'make install' command:

    $ make samples

Configuration
-------------

Refer to the `res_discovery_consul.conf.sample` file for detailed configuration options.

Key aspects of the configuration include:
- Enabling the module and Consul agent details (host, port, token).
- Service registration details (service ID, name, tags, address, port to advertise).
- Health check mechanism.

**Health Check Mechanism:**

This module implements an HTTP health check to integrate with Consul.
- If `check = yes` in `res_discovery_consul.conf`, the module will register an HTTP health check with Consul.
- Asterisk's built-in HTTP server must be enabled (`http.conf`), and the configured `check_http_port` (default 8088) must be accessible by the Consul agent.
- The module exposes a specific HTTP endpoint within Asterisk: `http://<asterisk_ip>:<check_http_port>/res_discovery_consul/check_eid` (Note: If you've modified this path in the source, update documentation accordingly).

**EID-Specific Health Check for Robustness:**

To prevent issues where a new Asterisk instance reuses an IP address of a previously deregistered instance (potentially leading to stale entries in Consul if only basic IP/port checks are used), this module implements an Endpoint Identifier (EID) specific health check.
- When registering with Consul, the module includes the unique EID of the Asterisk instance (`global_config.id`, typically derived from a MAC address or a UUID) in the health check URL as a query parameter (`?expected_eid=<instance_eid>`).
- The HTTP endpoint `/res_discovery_consul/check_eid` served by this module verifies that the `expected_eid` from Consul's health check query matches the actual EID of the running Asterisk instance.
- If the EIDs do not match, the endpoint returns an HTTP 404 error, signaling to Consul that this is not the correct instance. Consul will then mark the service as critical and eventually deregister it based on `DeregisterCriticalServiceAfter`.
- This ensures that only the legitimately running Asterisk instance for a given EID remains registered and healthy in Consul.

**Health Check Configuration Options (in `res_discovery_consul.conf` under `[consul]`):**
- `check_interval`: How often Consul pings the health check endpoint (e.g., "15s").
- `check_timeout`: How long Consul waits for a response from the health check endpoint (e.g., "3s"). This is the timeout for the HTTP request itself.
- `check_deregister_after`: How long a service stays in a critical state (due to failing health checks) before Consul automatically deregisters it (e.g., "30s").

To use
------

Loading module:

    asterisk -r
    CLI> module unload res_discovery_consul.so
    CLI> module load res_discovery_consul.so

Show settings on CLI:

    asterisk -r
    CLI> discovery show settings
    (This will display current settings, including check timeout and deregister after values)

To enable or disable maintenance mode for the service in Consul:

    asterisk -r
    CLI> discovery set maintenance on
    CLI> discovery set maintenance off

Show current module and Consul registration status:

    asterisk -r
    CLI> discovery show status

Roadmap
-------

- API consul via https
- Support for consul KV, if you want to add specific information
- Support TTL check from consul (https://consul.io/docs/agent/checks.html) - *The current HTTP EID check provides strong, active validation. TTL could complement this for scenarios where Asterisk pushes its health.*
- Disable or enable check via CLI
- Fire an event on register/deregister (https://consul.io/docs/agent/http/event.html)

Docker
------

Edit the sample configuration to have the correct settings for your Docker environment.
To build an image to test with Docker:

    docker build -t asterisk-consul .
    docker run -it asterisk-consul bash # Then run 'asterisk' inside the container

UDP issue
---------

If you encounter UDP issues when running in Docker (often related to NAT and conntrack), this command might help clear conntrack entries. Use with caution and understand its implications:

    docker run --net=host --privileged --rm cap10morgan/conntrack -D -p udp

Docker-compose
--------------

    docker-compose build --no-cache
    docker-compose up -d
    # Example of scaling Asterisk services
    docker-compose scale asterisk=5

Consul Web UI (default token might be configured in docker-compose.yml or Consul config):

    http://<consul_ip>:8500/ui

ARI interface (if configured and exposed, example user/pass 'xivo/xivo'):

    http://<asterisk_ip>:8088/ari 

Schema
------

![Asterisk Consul screenshot](/contribs/images/asterisk-consul.png?raw=true "Asterisk Consul")
![Asterisk Consul Kamailio screenshot](/contribs/images/asterisk-consul-kamailio.png?raw=true "Asterisk Consul Kamailio")

Integration Tests
-----------------

To execute the integration tests:

    cd integration_tests
    pip install -r test-requirements.txt
    make test-setup
    make test
