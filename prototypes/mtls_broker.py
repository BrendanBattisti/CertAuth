"""
mTLS Token Broker Prototype

This prototype demonstrates the mTLS communication layer that:
- Terminates mTLS connections from devices
- Validates device certificates
- Exchanges authenticated device context for tokens
"""

import ssl
import socket
import json
import time
from typing import Optional, Dict
from datetime import datetime, timedelta
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

# Import shared certificate utilities
import sys
sys.path.append('..')
from shared.cert_utils import CertificateStore


class MockKeycloak:
    """Mock Keycloak identity provider for token issuance."""
    
    def __init__(self, secret_key: str = "mock-secret-key"):
        self.secret_key = secret_key
    
    def issue_token(self, device_id: str, scopes: list = None, attributes: Dict = None) -> str:
        """
        Issue a JWT access token for a device.
        
        Args:
            device_id: Device identifier
            scopes: List of OAuth scopes
            attributes: Device attributes to include in token
        
        Returns:
            JWT token string
        """
        scopes = scopes or ["read", "write"]
        now = datetime.utcnow()
        
        payload = {
            "sub": device_id,
            "iss": "mock-keycloak",
            "aud": "cloud-services",
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "scope": " ".join(scopes),
            "device_id": device_id,
            "device_attributes": attributes or {}
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token


class MTLSBroker:
    """mTLS Token Broker that handles device authentication and token issuance."""
    
    def __init__(self, host: str = "localhost", port: int = 8443, cert_store: CertificateStore = None):
        self.host = host
        self.port = port
        self.cert_store = cert_store or CertificateStore()
        self.keycloak = MockKeycloak()
        
        # Create SSL context for mTLS
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context.check_hostname = False
        
        # Load CA certificate for client verification
        ca_cert = self.cert_store.get_ca_certificate()
        self.ssl_context.load_verify_locations(cadata=ca_cert.decode())
        
        # Create broker certificate for server TLS
        broker_cert, broker_key = self._create_broker_certificate()
        self.ssl_context.load_cert_chain(
            certfile=self._save_temp_cert(broker_cert, "broker_cert.pem"),
            keyfile=self._save_temp_cert(broker_key, "broker_key.pem")
        )
    
    def _create_broker_certificate(self):
        """Create a certificate for the broker server."""
        broker_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "mtls-broker"),
        ])
        
        broker_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            broker_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(self.cert_store.ca_key, hashes.SHA256(), default_backend())
        
        cert_pem = broker_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = broker_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return cert_pem, key_pem
    
    def _save_temp_cert(self, cert_data: bytes, filename: str) -> str:
        """Save certificate data to a temporary file."""
        import tempfile
        import os
        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)
        with open(filepath, "wb") as f:
            f.write(cert_data)
        return filepath
    
    def handle_client(self, conn: ssl.SSLSocket):
        """Handle a client connection."""
        try:
            # Get client certificate
            client_cert = conn.getpeercert(binary_form=True)
            if not client_cert:
                conn.sendall(b"ERROR: No client certificate provided\n")
                return
            
            # Validate certificate
            is_valid, device_id, attributes = self.cert_store.validate_certificate(client_cert)
            
            if not is_valid:
                conn.sendall(b"ERROR: Invalid or revoked certificate\n")
                return
            
            print(f"[Broker] Authenticated device: {device_id}")
            print(f"[Broker] Device attributes: {attributes}")
            
            # Read token request
            request_data = conn.recv(4096).decode('utf-8')
            try:
                request = json.loads(request_data)
                scopes = request.get("scopes", ["read", "write"])
            except:
                scopes = ["read", "write"]
            
            # Request token from Keycloak (mock)
            token = self.keycloak.issue_token(device_id, scopes, attributes)
            
            # Send token to device
            response = {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": " ".join(scopes)
            }
            
            conn.sendall(json.dumps(response).encode('utf-8'))
            print(f"[Broker] Issued token for device: {device_id}")
            
        except Exception as e:
            print(f"[Broker] Error handling client: {e}")
            conn.sendall(f"ERROR: {str(e)}\n".encode('utf-8'))
        finally:
            conn.close()
    
    def start(self):
        """Start the mTLS broker server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        print(f"[Broker] mTLS Token Broker listening on {self.host}:{self.port}")
        
        while True:
            try:
                client_sock, addr = sock.accept()
                conn = self.ssl_context.wrap_socket(client_sock, server_side=True)
                print(f"[Broker] Connection from {addr}")
                self.handle_client(conn)
            except KeyboardInterrupt:
                print("\n[Broker] Shutting down...")
                break
            except Exception as e:
                print(f"[Broker] Error accepting connection: {e}")


if __name__ == "__main__":
    broker = MTLSBroker()
    broker.start()
