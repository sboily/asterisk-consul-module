# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `res_discovery_consul`, an Asterisk module that registers Asterisk instances as services in HashiCorp Consul for service discovery. It's written in C and uses libcurl to communicate with the Consul REST API.

## Build Commands

```bash
# Build the module
make

# Install the module to /usr/lib/asterisk/modules/
make install

# Install sample configuration to /etc/asterisk/
make samples

# Clean build artifacts
make clean
```

## Integration Tests

```bash
cd integration_tests
pip install -r test-requirements.txt
make test-setup  # Pull Docker images
make test        # Run nosetests
```

## Architecture

### Core Module (res_discovery_consul.c)

The module implements:
- **Consul Registration**: Registers Asterisk as a service with Consul on module load, deregisters on unload
- **HTTP Health Check Endpoint**: Exposes `/consul_check` via Asterisk's HTTP server for EID-based health verification
- **Metadata Profiles**: Supports custom metadata profiles (group, priority, weight, max_calls, flags) for telecom routing integration
- **CLI Commands**: `discovery show settings`, `discovery show status`, `discovery set maintenance {on|off}`
- **Manager Interface**: `DiscoverySetMaintenance` action and `DiscoveryRegister`/`DiscoveryDeregister` events

### Key Structures

- `struct discovery_config` (global_config): Main configuration holding Consul connection details, service registration info, and health check settings
- `struct metadata_profile` (global_metadata): Telecom routing metadata for SIP proxy/dispatcher integration

### Configuration

Configuration file: `res_discovery_consul.conf`
- `[general]`: Module enable/disable
- `[consul]`: Consul agent settings, service registration, health check config, metadata_profile reference
- `[metadata_*]`: Named metadata profiles with routing parameters

### Health Check Mechanism

The module uses an EID (Endpoint Identifier) based health check to prevent stale Consul entries when IPs are reused:
1. Asterisk registers with Consul including a health check URL with `?expected_eid=<instance_eid>`
2. Consul calls the `/consul_check` endpoint periodically
3. The endpoint validates the expected EID matches the running instance's EID
4. Mismatches return HTTP 404, causing Consul to mark the service critical and eventually deregister it

### Dependencies

- Asterisk 13.x+ development headers
- libcurl
- Asterisk HTTP server enabled (for health checks)
