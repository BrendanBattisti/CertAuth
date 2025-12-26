---

## 12. Threat Model

This section describes the primary trust boundaries, assets, and threats associated with the proposed token brokering architecture, along with corresponding mitigations.

### 12.1 High-Level Threat Model Diagram

```mermaid
flowchart LR
    Device[Managed Device\n(Device Cert + Private Key)]
    Broker[mTLS Token Broker]
    IdP[Keycloak\nIdentity Provider]
    Services[Cloud Services]

    Device -->|mTLS| Broker
    Broker -->|Token Exchange| IdP
    IdP -->|JWT Access Token| Broker
    Broker -->|JWT Access Token| Device
    Device -->|Bearer Token| Services

    subgraph Untrusted_Network["Untrusted Network"]
        Device
        Services
    end

    subgraph Trusted_Cloud["Trusted Cloud Environment"]
        Broker
        IdP
    end
