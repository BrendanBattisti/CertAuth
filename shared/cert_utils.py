"""
Shared Certificate Utilities Library

This module provides certificate management functionality to mimic
the PKI system used for device authentication and trust.
"""

import os
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


class CertificateStore:
    """Manages certificates, private keys, and CA chains."""
    
    def __init__(self, store_dir: str = "./cert_store"):
        self.store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)
        self.devices: Dict[str, Dict] = {}
        self.ca_cert = None
        self.ca_key = None
        self._load_or_create_ca()
    
    def _load_or_create_ca(self):
        """Load or create a root CA certificate."""
        ca_cert_path = os.path.join(self.store_dir, "ca_cert.pem")
        ca_key_path = os.path.join(self.store_dir, "ca_key.pem")
        
        if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
            with open(ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            with open(ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), None, default_backend())
        else:
            self._create_ca()
    
    def _create_ca(self):
        """Create a root CA certificate."""
        # Generate CA private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Device Trust CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
        ])
        
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())
        
        # Save CA cert and key
        ca_cert_path = os.path.join(self.store_dir, "ca_cert.pem")
        ca_key_path = os.path.join(self.store_dir, "ca_key.pem")
        
        with open(ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def create_device_certificate(self, device_id: str, attributes: Optional[Dict] = None) -> Tuple[bytes, bytes]:
        """
        Create a device certificate and private key.
        
        Args:
            device_id: Unique device identifier
            attributes: Optional metadata (e.g., device_type, location)
        
        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        # Generate device private key
        device_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create device certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Device Trust"),
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ])
        
        # Add custom attributes as extensions if provided
        extensions = []
        if attributes:
            # Store attributes as a custom extension (in real implementation, use proper OIDs)
            attrs_json = json.dumps(attributes)
            extensions.append(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9.1"),  # Placeholder OID
                    attrs_json.encode()
                )
            )
        
        device_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            device_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{device_id}.device.local")
            ]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256(), default_backend())
        
        cert_pem = device_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = device_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Store device info
        self.devices[device_id] = {
            "cert": device_cert,
            "key": device_key,
            "attributes": attributes or {},
            "revoked": False
        }
        
        # Save to disk
        device_dir = os.path.join(self.store_dir, "devices", device_id)
        os.makedirs(device_dir, exist_ok=True)
        
        with open(os.path.join(device_dir, "cert.pem"), "wb") as f:
            f.write(cert_pem)
        
        with open(os.path.join(device_dir, "key.pem"), "wb") as f:
            f.write(key_pem)
        
        return cert_pem, key_pem
    
    def validate_certificate(self, cert_pem: bytes) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Validate a device certificate.
        
        Args:
            cert_pem: Certificate in PEM format
        
        Returns:
            Tuple of (is_valid, device_id, attributes)
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Check if certificate is signed by our CA
            try:
                self.ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    hashes.SHA256()
                )
            except Exception:
                return False, None, None
            
            # Check if certificate is expired
            if cert.not_valid_after < datetime.utcnow():
                return False, None, None
            
            # Extract device ID from CN
            device_id = None
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    device_id = attr.value
                    break
            
            if not device_id:
                return False, None, None
            
            # Check revocation status
            if device_id in self.devices and self.devices[device_id]["revoked"]:
                return False, None, None
            
            # Extract attributes
            attributes = self.devices.get(device_id, {}).get("attributes", {})
            
            return True, device_id, attributes
            
        except Exception as e:
            print(f"Certificate validation error: {e}")
            return False, None, None
    
    def revoke_certificate(self, device_id: str):
        """Revoke a device certificate."""
        if device_id in self.devices:
            self.devices[device_id]["revoked"] = True
    
    def get_ca_certificate(self) -> bytes:
        """Get the CA certificate in PEM format."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)
    
    def get_device_certificate(self, device_id: str) -> Optional[bytes]:
        """Get a device certificate by ID."""
        if device_id in self.devices:
            return self.devices[device_id]["cert"].public_bytes(serialization.Encoding.PEM)
        return None
    
    def get_device_private_key(self, device_id: str) -> Optional[bytes]:
        """Get a device private key by ID."""
        if device_id in self.devices:
            return self.devices[device_id]["key"].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        return None
