# Prototypes

This directory contains Python prototypes for the core components of the token brokering system.

## Components

### 1. Shared Certificate Library (`../shared/cert_utils.py`)

A shared library that mimics the certificate system:
- Creates and manages a root CA
- Generates device certificates signed by the CA
- Validates certificates and checks revocation
- Stores device attributes and metadata

### 2. mTLS Broker (`mtls_broker.py`)

The mTLS communication layer that:
- Terminates mTLS connections from devices
- Validates device certificates using the shared certificate library
- Exchanges authenticated device context for JWT tokens (via mock Keycloak)
- Issues short-lived, scoped access tokens

**Usage:**
```bash
python prototypes/mtls_broker.py
```

The broker listens on `localhost:8443` by default.

### 3. Device Authentication (`device_auth.py`)

Demonstrates how a device authenticates using mTLS:
- Establishes mTLS connection to broker
- Presents device certificate
- Receives access token
- Uses token to access cloud services

**Usage:**
```bash
python prototypes/device_auth.py
```

### 4. CCF Application Delegation (`ccf_app.py`)

Shows how CCF applications on devices can:
- Request scoped tokens using device certificates
- Avoid embedding secrets in applications
- Delegate access control to Keycloak

**Usage:**
```bash
python prototypes/ccf_app.py
```

### 5. Federated Credentials (`federated_credentials.py`)

Demonstrates federated authentication for customer apps:
- Customer apps authenticate without sharing credentials with device
- Device certificate proves device trust
- Customer credentials are handled by broker/Keycloak
- Customer-scoped tokens are issued

**Usage:**
```bash
python prototypes/federated_credentials.py
```

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run individual prototypes to see them in action.

## Architecture Notes

- **Certificate Store**: All prototypes use the shared `CertificateStore` class to manage PKI
- **Mock Keycloak**: The broker includes a simple mock Keycloak for token issuance (in production, this would be a real Keycloak instance)
- **JWT Tokens**: Tokens are issued as JWTs with device/customer attributes and scopes
- **mTLS**: Uses Python's `ssl` module for mutual TLS authentication

## Testing the Full Flow

To test the complete flow:

1. Start the mTLS broker in one terminal:
```bash
python prototypes/mtls_broker.py
```

2. Run device authentication in another terminal:
```bash
python prototypes/device_auth.py
```

The device will authenticate and receive a token from the broker.

## File Structure

```
/workspace/
├── shared/
│   └── cert_utils.py          # Shared certificate management library
├── prototypes/
│   ├── mtls_broker.py         # mTLS token broker
│   ├── device_auth.py         # Device authentication client
│   ├── ccf_app.py             # CCF application delegation
│   └── federated_credentials.py # Federated credentials
└── requirements.txt           # Python dependencies
```
