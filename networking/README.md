# Quantum-Resistant P2P Agent

A proof-of-concept implementation of a peer-to-peer agent system featuring quantum-resistant cryptography, secure WebSocket communication, and TLS 1.3 encryption.

## Features

- Post-quantum cryptography using Kyber768 for key encapsulation
- Classical cryptography with Ed25519 for digital signatures
- TLS 1.3 for secure transport layer
- ChaCha20-Poly1305 for authenticated encryption
- Secure WebSocket communication
- Automatic message retries and buffering
- Self-signed certificate generation for testing

## Requirements

- Python 3.7+
- liboqs (Open Quantum Safe)
- Required Python packages:
  ```
  websockets
  cryptography
  python3-liboqs
  ```

## Installation

1. Install the required dependencies:
   ```bash
   pip install websockets cryptography python3-liboqs
   ```

2. Clone the repository and navigate to the project directory:
   ```bash
   git clone <repository-url>
   cd <project-directory>
   ```

## Usage

1. Basic example of creating two P2P agents:

```python
import asyncio
from networking.agent_websockets import P2PAgent, generate_self_signed_cert

async def main():
    # Generate test certificates
    cert_path = "cert.pem"
    key_path = "key.pem"
    generate_self_signed_cert(cert_path, key_path)
    
    # Create agents
    agent1 = P2PAgent("agent1", 8001, cert_path, key_path)
    agent2 = P2PAgent("agent2", 8002, cert_path, key_path)
    
    # Start secure servers
    await asyncio.gather(
        agent1.start(),
        agent2.start()
    )
    
    # Connect peers
    await agent1.connect_to_peer("agent2", "wss://localhost:8002")
    
    # Send a message
    await agent1.send_message("agent2", {
        "type": "message",
        "content": "Hello, Agent 2!"
    })

if __name__ == "__main__":
    asyncio.run(main())
```

## Security Features

### Quantum Resistance
- Uses Kyber768 for post-quantum key encapsulation
- Resistant against attacks from quantum computers

### Classical Cryptography
- Ed25519 for digital signatures
- ChaCha20-Poly1305 for authenticated encryption
- HKDF for key derivation

### Transport Security
- TLS 1.3 with strong cipher suites
- Certificate validation
- Perfect forward secrecy

## Architecture

The P2PAgent class provides:
- Secure peer-to-peer connections
- Message encryption and signing
- Automatic retry mechanism
- Message buffering
- Custom message handlers
- Certificate management

## Development

This is a proof-of-concept implementation. For production use, consider:
- Implementing proper certificate management (The self-signed certificate generation is only for testing - this would need proper PKI in production)
- Adding peer discovery mechanisms (this would need a proper discovery service in production)
- Implementing proper error handling and logging (this would require me working on it for 10 more minutes)
- Adding message persistence (this would require creating a message queue and a message broker)
- Implementing proper key management (this would require creating a key management service)
- Adding proper logging and monitoring (I suggest Sentry for hosted services, and DIY for self-hosted services, especially in combination with Redis)

## License

Apache 2.0

## Contributing

Tell me where it sucks and I'll fix it.