"""
Device Authentication Prototype

This prototype demonstrates how a device authenticates using mTLS
and receives tokens from the broker.
"""

import ssl
import socket
import json
import sys
import os

# Import shared certificate utilities
sys.path.append('..')
from shared.cert_utils import CertificateStore


class DeviceClient:
    """Represents a managed device that authenticates via mTLS."""
    
    def __init__(self, device_id: str, cert_store: CertificateStore = None):
        self.device_id = device_id
        self.cert_store = cert_store or CertificateStore()
        
        # Ensure device certificate exists
        device_dir = os.path.join(self.cert_store.store_dir, "devices", device_id)
        cert_path = os.path.join(device_dir, "cert.pem")
        key_path = os.path.join(device_dir, "key.pem")
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            print(f"[Device {device_id}] Creating device certificate...")
            self.cert_store.create_device_certificate(
                device_id,
                attributes={"device_type": "managed", "location": "field"}
            )
        
        self.cert_path = cert_path
        self.key_path = key_path
        self.access_token = None
    
    def authenticate(self, broker_host: str = "localhost", broker_port: int = 8443, scopes: list = None) -> dict:
        """
        Authenticate with the mTLS broker and receive an access token.
        
        Args:
            broker_host: Broker hostname
            broker_port: Broker port
            scopes: Requested OAuth scopes
        
        Returns:
            Token response dictionary
        """
        scopes = scopes or ["read", "write"]
        
        # Create SSL context for mTLS client
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE  # In production, verify broker cert
        
        # Load device certificate and key
        ssl_context.load_cert_chain(self.cert_path, self.key_path)
        
        # Load CA certificate for broker verification (in production)
        ca_cert = self.cert_store.get_ca_certificate()
        ssl_context.load_verify_locations(cadata=ca_cert.decode())
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        try:
            # Connect to broker
            print(f"[Device {self.device_id}] Connecting to broker at {broker_host}:{broker_port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = ssl_context.wrap_socket(sock, server_hostname=broker_host)
            conn.connect((broker_host, broker_port))
            
            print(f"[Device {self.device_id}] mTLS connection established")
            
            # Send token request
            request = {
                "scopes": scopes,
                "grant_type": "client_credentials"
            }
            conn.sendall(json.dumps(request).encode('utf-8'))
            
            # Receive token response
            response_data = conn.recv(4096).decode('utf-8')
            conn.close()
            
            try:
                response = json.loads(response_data)
                if "access_token" in response:
                    self.access_token = response["access_token"]
                    print(f"[Device {self.device_id}] Authentication successful!")
                    print(f"[Device {self.device_id}] Token: {self.access_token[:50]}...")
                    return response
                else:
                    print(f"[Device {self.device_id}] Authentication failed: {response_data}")
                    return {"error": response_data}
            except json.JSONDecodeError:
                print(f"[Device {self.device_id}] Invalid response: {response_data}")
                return {"error": response_data}
                
        except Exception as e:
            print(f"[Device {self.device_id}] Authentication error: {e}")
            return {"error": str(e)}
    
    def use_token(self, service_url: str, endpoint: str = "/api/data"):
        """
        Use the access token to access a cloud service.
        
        Args:
            service_url: Base URL of the service
            endpoint: API endpoint to access
        """
        if not self.access_token:
            print(f"[Device {self.device_id}] No access token. Please authenticate first.")
            return None
        
        import urllib.request
        import urllib.error
        
        url = f"{service_url}{endpoint}"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.access_token}")
        
        try:
            print(f"[Device {self.device_id}] Accessing {url}...")
            with urllib.request.urlopen(req) as response:
                data = response.read().decode('utf-8')
                print(f"[Device {self.device_id}] Service response: {data}")
                return data
        except urllib.error.HTTPError as e:
            print(f"[Device {self.device_id}] Service error: {e.code} - {e.reason}")
            return None


def demo_device_auth():
    """Demonstrate device authentication flow."""
    print("=== Device Authentication Prototype ===\n")
    
    # Initialize certificate store
    cert_store = CertificateStore()
    
    # Create a device
    device_id = "device-001"
    device = DeviceClient(device_id, cert_store)
    
    # Authenticate with broker
    print("\n1. Device authenticating with mTLS broker...")
    token_response = device.authenticate(scopes=["read", "write", "upload"])
    
    if "access_token" in token_response:
        print("\n2. Using token to access cloud service...")
        # In a real scenario, this would call an actual service
        print("   (Mock service call - token would be validated by service)")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_device_auth()
