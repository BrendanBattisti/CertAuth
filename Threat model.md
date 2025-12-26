---

## 12. Threat Model

This section describes the primary trust boundaries, assets, and threats associated with the proposed token brokering architecture, along with corresponding mitigations.

### 12.1 High-Level Threat Model Diagram

```mermaid
flowchart LR
    subgraph Untrusted_Network["Untrusted Network"]
        Device["Managed Device<br/>(Device Cert + Private Key)"]
        Services["Cloud Services"]
    end

    subgraph Trusted_Cloud["Trusted Cloud Environment"]
        Broker["mTLS Token Broker"]
        IdP["Keycloak<br/>Identity Provider"]
    end

    Device -->|mTLS| Broker
    Broker -->|Token Exchange| IdP
    IdP -->|JWT Access Token| Broker
    Broker -->|JWT Access Token| Device
    Device -->|Bearer Token| Services

```
