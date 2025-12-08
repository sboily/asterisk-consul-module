# Architecture Documentation

## High-Level Architecture Overview

res_discovery_consul is an Asterisk resource module that enables dynamic service discovery through HashiCorp Consul. It allows Asterisk instances to automatically register themselves with Consul, enabling other infrastructure components (SIP proxies, load balancers) to discover and route traffic to available Asterisk instances.

```mermaid
graph TB
    subgraph "Service Discovery Layer"
        CONSUL[("Consul<br/>Service Registry<br/>:8500")]
    end

    subgraph "Asterisk Instances"
        AST1["Asterisk #1<br/>res_discovery_consul<br/>:5060/UDP, :8088/HTTP"]
        AST2["Asterisk #2<br/>res_discovery_consul<br/>:5060/UDP, :8088/HTTP"]
        ASTn["Asterisk #n<br/>..."]
    end

    subgraph "Routing Layer"
        KAM["Kamailio<br/>SIP Proxy<br/>:5060/UDP"]
        HAP["HAProxy<br/>HTTP LB<br/>:8888"]
    end

    subgraph "Clients"
        SIP["SIP Clients<br/>(Linphone, etc.)"]
        ARI["ARI Clients<br/>(HTTP API)"]
    end

    AST1 -->|"Register/Deregister<br/>Health Check"| CONSUL
    AST2 -->|"Register/Deregister<br/>Health Check"| CONSUL
    ASTn -->|"Register/Deregister<br/>Health Check"| CONSUL

    CONSUL -->|"consul-template<br/>Watch Services"| KAM
    CONSUL -->|"consul-template<br/>Watch Services"| HAP

    SIP -->|"SIP"| KAM
    KAM -->|"Route to Asterisk"| AST1
    KAM -->|"Route to Asterisk"| AST2

    ARI -->|"HTTP"| HAP
    HAP -->|"Load Balance"| AST1
    HAP -->|"Load Balance"| AST2
```

## Component Breakdown and Responsibilities

### Core Components

| Component | Responsibility |
|-----------|----------------|
| **res_discovery_consul** | Asterisk module that handles Consul registration, health check endpoint, metadata management |
| **Consul** | Service registry storing registered Asterisk instances with health status |
| **consul-template** | Watches Consul for service changes and regenerates configuration files |
| **Kamailio** | SIP proxy that routes calls to discovered Asterisk instances via dispatcher module |
| **HAProxy** | HTTP load balancer for ARI (Asterisk REST Interface) endpoints |

### Module Internal Architecture

```mermaid
graph LR
    subgraph "res_discovery_consul.c"
        LOAD["load_module()"]
        UNLOAD["unload_module()"]
        RELOAD["reload_module()"]

        subgraph "Configuration"
            CONFIG["load_config()"]
            META["load_metadata_profile()"]
            ARI_DISC["discover_ari_settings()"]
        end

        subgraph "Consul API"
            REG["consul_register()"]
            DEREG["consul_deregister()"]
            MAINT["consul_maintenance_service()"]
            JSON["consul_put_json()"]
        end

        subgraph "HTTP Handler"
            HTTP["handle_http_check_eid()"]
        end

        subgraph "CLI/Manager"
            CLI_SET["discovery_cli_settings()"]
            CLI_STAT["discovery_cli_show_status()"]
            CLI_MAINT["discovery_cli_set_maintenance()"]
            MGR["manager_maintenance()"]
        end
    end

    LOAD --> CONFIG
    CONFIG --> META
    CONFIG --> ARI_DISC
    LOAD --> REG
    UNLOAD --> DEREG
    RELOAD --> CONFIG
    RELOAD --> REG

    REG --> JSON
    CLI_MAINT --> MAINT
    MGR --> MAINT
```

## Data Flow Between Components

### Service Registration Flow

```mermaid
sequenceDiagram
    participant AST as Asterisk
    participant MOD as res_discovery_consul
    participant CURL as libcurl
    participant CONSUL as Consul Agent

    AST->>MOD: load_module()
    MOD->>MOD: load_config()
    MOD->>MOD: load_metadata_profile()
    MOD->>MOD: discover_ari_settings()
    MOD->>MOD: consul_put_json()
    Note over MOD: Build JSON payload with<br/>ID, Name, Address, Port,<br/>Tags, Meta, Check
    MOD->>CURL: curl_easy_perform()
    CURL->>CONSUL: PUT /v1/agent/service/register
    CONSUL-->>CURL: 200 OK
    CURL-->>MOD: CURLE_OK
    MOD->>AST: manager_event("DiscoveryRegister")
```

### Health Check Flow

```mermaid
sequenceDiagram
    participant CONSUL as Consul Agent
    participant HTTP as Asterisk HTTP Server
    participant MOD as res_discovery_consul

    loop Every check_interval (15s default)
        CONSUL->>HTTP: GET /consul_check?expected_eid=<eid>
        HTTP->>MOD: handle_http_check_eid()
        MOD->>MOD: Compare expected_eid with global_config.id
        alt EID Match
            MOD-->>HTTP: 200 OK - EID Match
            HTTP-->>CONSUL: Service Healthy
        else EID Mismatch
            MOD-->>HTTP: 404 Not Found - EID Mismatch
            HTTP-->>CONSUL: Service Critical
            Note over CONSUL: After check_deregister_after,<br/>auto-deregister service
        end
    end
```

### Dynamic Configuration Update Flow

```mermaid
sequenceDiagram
    participant CONSUL as Consul
    participant CT as consul-template
    participant KAM as Kamailio
    participant HAP as HAProxy

    Note over CONSUL: Asterisk registers/deregisters
    CONSUL->>CT: Service change notification

    par Kamailio Update
        CT->>CT: Render kamailio.ctmpl
        CT->>KAM: Write dispatcher.list
        CT->>KAM: Reload (pkill + restart)
    and HAProxy Update
        CT->>CT: Render ha-proxy.ctmpl
        CT->>HAP: Write haproxy.cfg
        CT->>HAP: Reload
    end
```

## External Integrations and Third-Party Services

### Consul REST API Integration

The module communicates with Consul using the following API endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/agent/service/register` | PUT | Register service with health check |
| `/v1/agent/service/deregister/:id` | PUT | Deregister service |
| `/v1/agent/service/maintenance/:id` | PUT | Enable/disable maintenance mode |
| `/v1/agent/health/service/id/:id` | GET | Check service health status |

### consul-template Integration

consul-template watches Consul's service catalog and regenerates configuration files:

**Kamailio dispatcher.list template:**
```hcl
{{range service "asterisk"}}
1 sip:{{.Address}}:{{.Port}}
{{end}}
```

**HAProxy backend template:**
```hcl
{{range service "asterisk"}}
    server {{.Node}} {{.Address}}:8888 check
{{end}}
```

## Infrastructure and Deployment Topology

### Docker Compose Deployment

```mermaid
graph TB
    subgraph "Docker Network"
        subgraph "Service Discovery"
            CONSUL["consul<br/>progrium/consul:latest<br/>:8500"]
        end

        subgraph "Telephony Services"
            AST["asterisk<br/>Custom image<br/>:5060/UDP, :8888"]
        end

        subgraph "Routing Infrastructure"
            KAM["kamailio<br/>Custom + consul-template<br/>:5060/UDP"]
            HAP["lb (haproxy)<br/>Custom + consul-template<br/>:8888, :1936"]
        end

        subgraph "Test Clients"
            PHONE["phone (linphone)<br/>Custom image"]
        end
    end

    AST -->|links| CONSUL
    KAM -->|links| CONSUL
    HAP -->|links| CONSUL
    PHONE -->|links| AST
    PHONE -->|links| KAM
```

### Scaling Considerations

```mermaid
graph LR
    subgraph "Horizontal Scaling"
        AST1["Asterisk #1"]
        AST2["Asterisk #2"]
        AST3["Asterisk #3"]
        ASTn["Asterisk #n"]
    end

    subgraph "Service Discovery"
        CONSUL["Consul Cluster"]
    end

    subgraph "Load Distribution"
        KAM["Kamailio<br/>Dispatcher Module"]
        HAP["HAProxy<br/>Round-Robin"]
    end

    AST1 & AST2 & AST3 & ASTn --> CONSUL
    CONSUL --> KAM & HAP
```

**Scaling commands:**
```bash
# Scale Asterisk instances
docker-compose scale asterisk=5
```

## Security Architecture

### Authentication & Authorization

```mermaid
graph TB
    subgraph "Consul Security"
        TOKEN["ACL Token<br/>(token in config)"]
    end

    subgraph "Asterisk Security"
        ARI_AUTH["ARI Authentication<br/>(xivo/xivo)"]
        MGR_AUTH["Manager Auth<br/>(manager.conf)"]
    end

    subgraph "HAProxy Security"
        STATS["Stats Auth<br/>(xivo/xivo)"]
    end

    TOKEN -->|"X-Consul-Token header"| CONSUL_API["Consul API"]
    ARI_AUTH -->|"HTTP Basic Auth"| ARI_EP["ARI Endpoints"]
    STATS -->|"HTTP Basic Auth"| STATS_EP["HAProxy Stats :1936"]
```

### Network Security Considerations

| Port | Protocol | Service | Security Notes |
|------|----------|---------|----------------|
| 5060 | UDP | SIP | Should be firewalled to trusted networks |
| 8088 | TCP | ARI/HTTP | Health check port, requires auth for ARI |
| 8500 | TCP | Consul | Should use ACL tokens in production |
| 1936 | TCP | HAProxy Stats | Requires authentication |

### Health Check Security

The EID-based health check provides security against stale service entries:

1. **Problem**: When an IP address is reassigned, Consul may still have the old service registered
2. **Solution**: Each health check includes `expected_eid` parameter unique to the instance
3. **Validation**: Health endpoint verifies EID matches, returns 404 on mismatch
4. **Auto-cleanup**: Consul deregisters after `check_deregister_after` timeout

### Token Configuration

```ini
# res_discovery_consul.conf
[consul]
token=your-consul-token-here
```

The token is appended as a query parameter to all Consul API requests:
- `?token=<token>` for registration/deregistration
- `&token=<token>` for maintenance operations

## Deployment Patterns

### Single Instance

```
Consul <---> Asterisk (with res_discovery_consul)
```

### Multi-Instance with Load Balancing

```
                     ┌─── Asterisk #1
Consul <---> HAProxy ├─── Asterisk #2
                     └─── Asterisk #3
```

### Full Stack with SIP Proxy

```
                      ┌─── Asterisk #1
SIP Client --> Kamailio ├─── Asterisk #2
                      └─── Asterisk #3
                           │
                       Consul (Service Registry)
```
