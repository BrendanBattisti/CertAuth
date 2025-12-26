"""
CCF Application Delegation Prototype

This prototype demonstrates how CCF applications on devices can request
scoped tokens using device certificates instead of embedding secrets.
"""

import sys
import json
import os

# Import shared certificate utilities
sys.path.append('..')
from shared.cert_utils import CertificateStore
from prototypes.device_auth import DeviceClient


class CCFApplication:
    """
    Represents a CCF application running on a device.
    Uses device certificate to request scoped tokens.
    """
    
    def __init__(self, app_name: str, device_id: str, cert_store: CertificateStore = None):
        self.app_name = app_name
        self.device_id = device_id
        self.cert_store = cert_store or CertificateStore()
        self.device_client = DeviceClient(device_id, cert_store)
        self.app_token = None
    
    def request_scoped_token(self, scopes: list, broker_host: str = "localhost", broker_port: int = 8443) -> dict:
        """
        Request a scoped token for this CCF application.
        
        Args:
            scopes: Application-specific scopes (e.g., ["ccf:read", "ccf:write"])
            broker_host: Broker hostname
            broker_port: Broker port
        
        Returns:
            Token response dictionary
        """
        print(f"[CCF App: {self.app_name}] Requesting scoped token with scopes: {scopes}")
        
        # Use device certificate to authenticate
        # In real implementation, the app would use the device's certificate
        # without needing to know the private key directly
        token_response = self.device_client.authenticate(
            broker_host=broker_host,
            broker_port=broker_port,
            scopes=scopes
        )
        
        if "access_token" in token_response:
            self.app_token = token_response["access_token"]
            print(f"[CCF App: {self.app_name}] Received scoped token")
            
            # Decode token to show scopes (in production, validate signature)
            import jwt
            try:
                decoded = jwt.decode(self.app_token, options={"verify_signature": False})
                token_scopes = decoded.get("scope", "").split()
                print(f"[CCF App: {self.app_name}] Token scopes: {token_scopes}")
            except:
                pass
        
        return token_response
    
    def access_cloud_service(self, service_url: str, endpoint: str, operation: str = "read"):
        """
        Access a cloud service using the app's scoped token.
        
        Args:
            service_url: Base URL of the service
            endpoint: API endpoint
            operation: Operation type (read/write)
        """
        if not self.app_token:
            print(f"[CCF App: {self.app_name}] No token available. Request token first.")
            return None
        
        import urllib.request
        import urllib.error
        
        url = f"{service_url}{endpoint}"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.app_token}")
        req.add_header("X-App-Name", self.app_name)
        
        try:
            print(f"[CCF App: {self.app_name}] Accessing {url} with {operation} operation...")
            with urllib.request.urlopen(req) as response:
                data = response.read().decode('utf-8')
                print(f"[CCF App: {self.app_name}] Service response: {data}")
                return data
        except urllib.error.HTTPError as e:
            print(f"[CCF App: {self.app_name}] Service error: {e.code} - {e.reason}")
            return None


def demo_ccf_app():
    """Demonstrate CCF application delegation flow."""
    print("=== CCF Application Delegation Prototype ===\n")
    
    # Initialize certificate store
    cert_store = CertificateStore()
    
    # Create a device
    device_id = "device-ccf-001"
    
    # Ensure device certificate exists
    device_dir = os.path.join(cert_store.store_dir, "devices", device_id)
    if not os.path.exists(os.path.join(device_dir, "cert.pem")):
        cert_store.create_device_certificate(
            device_id,
            attributes={"device_type": "ccf-enabled", "location": "field"}
        )
    
    # Create CCF application
    app = CCFApplication("data-collector", device_id, cert_store)
    
    # Request scoped token for CCF operations
    print("\n1. CCF app requesting scoped token...")
    scopes = ["ccf:read", "ccf:write", "cloud:upload"]
    token_response = app.request_scoped_token(scopes)
    
    if "access_token" in token_response:
        print("\n2. CCF app using token to access cloud service...")
        # In a real scenario, this would call an actual service
        print("   (Mock service call - token would be validated by service)")
        print("   App can now perform operations without embedded secrets!")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_ccf_app()
