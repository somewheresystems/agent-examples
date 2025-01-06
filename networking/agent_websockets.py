import asyncio
import json
import ssl
from typing import Dict, Optional, Callable
import websockets
import hashlib
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from oqs import KeyEncapsulation
import secrets
import pathlib

class P2PAgent:
    def __init__(self, agent_id: str, port: int, ssl_cert_path: str, ssl_key_path: str):
        self.agent_id = agent_id
        self.port = port
        self.peers: Dict[str, dict] = {}
        self.message_handlers: Dict[str, Callable] = {}
        self.message_buffer = []
        self.max_retries = 3
        self.retry_delay = 1.0
        
        # SSL/TLS context setup
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(ssl_cert_path, ssl_key_path)
        self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Client SSL context for verifying peer certificates
        self.client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_ssl_context.load_verify_locations(ssl_cert_path)
        self.client_ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.client_ssl_context.check_hostname = True
        self.client_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Post-quantum and ed25519 keys
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()
        
        # Kyber for quantum-resistant key exchange
        self.kyber = KeyEncapsulation('Kyber768')
        self.kyber_public_key = self.kyber.generate_keypair()
        
        # Session keys per peer
        self.session_keys: Dict[str, bytes] = {}
        
    def derive_session_key(self, shared_secret: bytes, peer_id: str) -> bytes:
        """Derive a session key using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"{self.agent_id}:{peer_id}".encode()
        )
        return hkdf.derive(shared_secret)
        
    async def start(self):
        """Start the agent's secure websocket server"""
        server = await websockets.serve(
            self._handle_connection,
            "localhost",
            self.port,
            ssl=self.ssl_context
        )
        print(f"Agent {self.agent_id} listening securely on port {self.port}")
        await server.wait_closed()
    
    async def connect_to_peer(self, peer_id: str, peer_url: str):
        """Establish quantum-resistant secure connection with a peer"""
        try:
            # Ensure we're using wss:// URL
            if not peer_url.startswith('wss://'):
                peer_url = peer_url.replace('ws://', 'wss://')
            
            async with websockets.connect(
                peer_url,
                ssl=self.client_ssl_context
            ) as websocket:
                # Initial handshake with Kyber public key and Ed25519 verify key
                handshake = {
                    "type": "handshake",
                    "agent_id": self.agent_id,
                    "kyber_public_key": self.kyber_public_key.hex(),
                    "verify_key": self.verify_key.public_bytes().hex()
                }
                
                # Sign the handshake
                signature = self.signing_key.sign(json.dumps(handshake).encode())
                handshake["signature"] = signature.hex()
                
                await websocket.send(json.dumps(handshake))
                response = await websocket.recv()
                response_data = json.loads(response)
                
                # Verify peer's signature
                peer_verify_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(response_data["verify_key"])
                )
                
                # Remove signature for verification
                sig = bytes.fromhex(response_data.pop("signature"))
                peer_verify_key.verify(sig, json.dumps(response_data).encode())
                
                # Perform Kyber key encapsulation
                peer_kyber_key = bytes.fromhex(response_data["kyber_public_key"])
                shared_secret = self.kyber.encapsulate(peer_kyber_key)
                
                # Derive session key
                session_key = self.derive_session_key(shared_secret, peer_id)
                self.session_keys[peer_id] = session_key
                
                # Store peer information
                self.peers[peer_id] = {
                    "url": peer_url,
                    "verify_key": peer_verify_key,
                    "kyber_public_key": peer_kyber_key
                }
                
                print(f"Securely connected to peer {peer_id} with quantum-resistant encryption over TLS 1.3")
                
        except Exception as e:
            print(f"Connection error: {e}")
            raise

    async def send_message(self, peer_id: str, message: dict, retry_count: int = 0):
        """Send encrypted message to a peer with quantum-resistant encryption over TLS"""
        if peer_id not in self.peers:
            raise ValueError(f"Unknown peer {peer_id}")
            
        try:
            async with websockets.connect(
                self.peers[peer_id]["url"],
                ssl=self.client_ssl_context
            ) as websocket:
                # Create AEAD cipher with session key
                nonce = secrets.token_bytes(12)
                cipher = ChaCha20Poly1305(self.session_keys[peer_id])
                
                # Encrypt message
                message_json = json.dumps(message)
                encrypted_message = cipher.encrypt(
                    nonce,
                    message_json.encode(),
                    self.agent_id.encode()
                )
                
                # Create full message with metadata
                full_message = {
                    "sender": self.agent_id,
                    "timestamp": time.time(),
                    "nonce": nonce.hex(),
                    "payload": encrypted_message.hex()
                }
                
                # Sign the message
                signature = self.signing_key.sign(
                    json.dumps(full_message).encode()
                )
                full_message["signature"] = signature.hex()
                
                await websocket.send(json.dumps(full_message))
                
                # Wait for acknowledgment
                ack = await websocket.recv()
                ack_data = json.loads(ack)
                
                if ack_data.get("status") != "received":
                    raise ConnectionError("Message not acknowledged")
                    
        except (websockets.exceptions.ConnectionClosed, ConnectionError) as e:
            if retry_count < self.max_retries:
                await asyncio.sleep(self.retry_delay * (retry_count + 1))
                await self.send_message(peer_id, message, retry_count + 1)
            else:
                self.message_buffer.append((peer_id, message))
                raise ConnectionError(f"Failed to send message to {peer_id}")

    # Rest of the class implementation remains the same...

# Helper function to generate self-signed certificates for testing
def generate_self_signed_cert(cert_path: str, key_path: str):
    """Generate a self-signed certificate for testing."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import datetime

    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,  # Increased key size for better security
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA384())  # Using SHA-384 for better security

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Example usage
async def main():
    # Generate certificates first
    cert_path = "cert.pem"
    key_path = "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    
    # Create two quantum-resistant agents with TLS support
    agent1 = P2PAgent("agent1", 8001, cert_path, key_path)
    agent2 = P2PAgent("agent2", 8002, cert_path, key_path)
    
    # Start their secure servers
    await asyncio.gather(
        agent1.start(),
        agent2.start()
    )
    
    # Connect them using wss://
    await agent1.connect_to_peer("agent2", "wss://localhost:8002")
    
    # Define message handlers
    async def handle_query(message):
        print(f"Received query: {message}")
        
    agent1.register_handler("query", handle_query)
    agent2.register_handler("query", handle_query)
    
    # Send test message
    await agent1.send_message("agent2", {
        "type": "query",
        "content": "Hello from agent1!"
    })

if __name__ == "__main__":
    asyncio.run(main())