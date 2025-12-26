"""
Federated Credentials Prototype

This prototype demonstrates how customer apps on devices can use
federated authentication without sharing credentials with the device.
"""

import sys
import json
import os

# Import shared certificate utilities
sys.path.append('..')
from shared.cert_utils import CertificateStore
from prototypes.device_auth import DeviceClient


class CustomerApplication:
    """
    Represents a customer application running on a managed device.
    Uses federated authentication to get customer-scoped tokens.
    """
    
    def __init__(self, app_name: str, customer_id: str, device_id: str, cert_store: CertificateStore = None):
        self.app_name = app_name
        self.customer_id = customer_id
        self.device_id = device_id
        self.cert_store = cert_store or CertificateStore()
        self.device_client = DeviceClient(device_id, cert_store)
        self.customer_token = None
    
    def federated_login(self, customer_credentials: dict, broker_host: str = "localhost", broker_port: int = 8443) -> dict:
        """
        Perform federated login using device certificate + customer credentials.
        
        In the real implementation:
        - Customer credentials are sent to the broker via secure channel
        - Broker validates device certificate (proving device trust)
        - Broker forwards customer credentials to Keycloak for federation
        - Keycloak issues customer-scoped token
        
        Args:
            customer_credentials: Customer authentication info (e.g., username/password, API key)
            broker_host: Broker hostname
            broker_port: Broker port
        
        Returns:
            Token response dictionary
        """
        print(f"[Customer App: {self.app_name}] Initiating federated login...")
        print(f"[Customer App: {self.app_name}] Customer ID: {self.customer_id}")
        print(f"[Customer App: {self.app_name}] Device ID: {self.device_id}")
        
        # Step 1: Authenticate device via mTLS
        print("\n1. Authenticating device via mTLS...")
        device_auth = self.device_client.authenticate(
            broker_host=broker_host,
            broker_port=broker_port,
            scopes=["federated:auth"]
        )
        
        if "error" in device_auth:
            return {"error": "Device authentication failed", "details": device_auth}
        
        # Step 2: Exchange device token + customer credentials for customer-scoped token
        print("\n2. Exchanging for customer-scoped token...")
        
        # In real implementation, this would be a separate API call to the broker
        # The broker would:
        # - Validate device token
        # - Forward customer credentials to Keycloak federation endpoint
        # - Return customer-scoped token
        
        # Mock: Generate customer-scoped token
        import jwt
        from datetime import datetime, timedelta
        
        now = datetime.utcnow()
        payload = {
            "sub": self.customer_id,
            "iss": "mock-keycloak-federated",
            "aud": "customer-services",
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "scope": "customer:read customer:write",
            "customer_id": self.customer_id,
            "device_id": self.device_id,
            "app_name": self.app_name,
            "federated": True
        }
        
        self.customer_token = jwt.encode(payload, "mock-secret-key", algorithm="HS256")
        
        print(f"[Customer App: {self.app_name}] Received customer-scoped token")
        print(f"[Customer App: {self.app_name}] Token is scoped to customer: {self.customer_id}")
        print(f"[Customer App: {self.app_name}] Device never saw customer credentials!")
        
        return {
            "access_token": self.customer_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "customer:read customer:write",
            "customer_id": self.customer_id
        }
    
    def access_customer_service(self, service_url: str, endpoint: str):
        """
        Access a customer service using the customer-scoped token.
        
        Args:
            service_url: Base URL of the customer service
            endpoint: API endpoint
        """
        if not self.customer_token:
            print(f"[Customer App: {self.app_name}] No customer token. Please login first.")
            return None
        
        import urllib.request
        import urllib.error
        
        url = f"{service_url}{endpoint}"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.customer_token}")
        req.add_header("X-Customer-ID", self.customer_id)
        req.add_header("X-App-Name", self.app_name)
        
        try:
            print(f"[Customer App: {self.app_name}] Accessing customer service at {url}...")
            with urllib.request.urlopen(req) as response:
                data = response.read().decode('utf-8')
                print(f"[Customer App: {self.app_name}] Service response: {data}")
                return data
        except urllib.error.HTTPError as e:
            print(f"[Customer App: {self.app_name}] Service error: {e.code} - {e.reason}")
            return None


def demo_federated_credentials():
    """Demonstrate federated credentials flow."""
    print("=== Federated Credentials Prototype ===\n")
    
    # Initialize certificate store
    cert_store = CertificateStore()
    
    # Create a device
    device_id = "device-customer-001"
    
    # Ensure device certificate exists
    device_dir = os.path.join(cert_store.store_dir, "devices", device_id)
    if not os.path.exists(os.path.join(device_dir, "cert.pem")):
        cert_store.create_device_certificate(
            device_id,
            attributes={"device_type": "customer-managed", "location": "field"}
        )
    
    # Create customer application
    customer_id = "customer-acme-corp"
    app = CustomerApplication("customer-analytics", customer_id, device_id, cert_store)
    
    # Perform federated login
    print("\n1. Customer app initiating federated login...")
    customer_credentials = {
        "username": "customer_user",
        "password": "***"  # Never actually stored on device
    }
    
    token_response = app.federated_login(customer_credentials)
    
    if "access_token" in token_response:
        print("\n2. Customer app using token to access customer service...")
        # In a real scenario, this would call an actual customer service
        print("   (Mock service call - token would be validated by service)")
        print("   Customer credentials were never exposed to the device!")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_federated_credentials()
