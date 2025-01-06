# Quantum-Resistant Redis Messaging Protocol

A production-ready implementation of a quantum-resistant messaging protocol using Redis as the transport layer. This implementation provides secure, authenticated, and encrypted communication between agents, resistant to both classical and quantum attacks.

## Features

### Security
- **Post-Quantum Cryptography**
  - Kyber768 for quantum-resistant key encapsulation
  - Future-proof against quantum computer attacks
- **Classical Cryptography**
  - Ed25519 for digital signatures
  - ChaCha20-Poly1305 for authenticated encryption
  - HKDF with SHA-256 for key derivation
- **Security Measures**
  - Automatic session key rotation
  - Message deduplication
  - Timestamp validation
  - Message authentication
  - Recipient validation
  - Secure random number generation

### Reliability
- **Connection Management**
  - Automatic peer discovery
  - Connection timeouts
  - Graceful shutdown
  - Connection retries
- **Message Handling**
  - Message acknowledgment
  - Message expiration
  - Message deduplication
  - Type-safe message handling

### Production Features
- **Monitoring & Logging**
  - Structured logging
  - Error tracking
  - Connection status monitoring
  - Message delivery status
- **Resource Management**
  - Automatic cleanup of old messages
  - Session key rotation
  - Memory leak prevention
  - Resource cleanup on shutdown
- **Error Handling**
  - Comprehensive exception hierarchy
  - Detailed error messages
  - Graceful error recovery
  - Connection error handling

## Requirements

- Python 3.7+
- Redis server 6.0+
- Required Python packages:
  ```
  redis-py[hiredis]>=4.5.0
  cryptography>=41.0.0
  python3-liboqs>=0.8.0
  ```

## Installation

1. Install the required dependencies:
   ```bash
   pip install redis[hiredis] cryptography python3-liboqs
   ```

2. Start a Redis server:
   ```bash
   redis-server
   ```

## Usage

### Basic Example

```python
import asyncio
from networking.redis.agent_redis import RedisAgent, Message

async def main():
    # Create agents
    agent1 = RedisAgent("agent1", "redis://localhost:6379")
    agent2 = RedisAgent("agent2", "redis://localhost:6379")
    
    # Start agents
    await agent1.start()
    await agent2.start()
    
    # Connect peers
    await agent1.connect_to_peer("agent2")
    await agent2.connect_to_peer("agent1")
    
    # Register message handler
    async def handle_message(message: Message):
        print(f"Received: {message.content}")
    
    agent2.register_handler("chat", handle_message)
    
    # Send message
    await agent1.send_message("agent2", Message(
        type="chat",
        content="Hello, secure world!"
    ))

if __name__ == "__main__":
    asyncio.run(main())
```

### Advanced Usage

#### Custom Message Types

```python
from dataclasses import dataclass
from typing import List

@dataclass
class ChatMessage(Message):
    room_id: str
    participants: List[str]
    encrypted_content: bytes

async def handle_chat(message: ChatMessage):
    # Handle encrypted group chat message
    pass

agent.register_handler("group_chat", handle_chat)
```

#### Secure Group Communication

```python
async def broadcast(agent: RedisAgent, peers: List[str], message: Message):
    """Send message to multiple peers"""
    for peer_id in peers:
        await agent.send_message(peer_id, message)
```

## Security Considerations

1. **Key Management**
   - Session keys are automatically rotated
   - Keys are never reused across sessions
   - Keys are securely derived using HKDF
   - Private keys are kept in memory only

2. **Message Security**
   - All messages are encrypted and authenticated
   - Messages include timestamps to prevent replay attacks
   - Messages are signed with Ed25519
   - Message integrity is verified

3. **Network Security**
   - Redis connections should use TLS in production
   - Redis AUTH should be enabled
   - Network segmentation is recommended
   - Firewall rules should be configured

## Production Deployment

1. **Redis Configuration**
   ```conf
   # redis.conf
   requirepass your_strong_password
   maxmemory 2gb
   maxmemory-policy allkeys-lru
   appendonly yes
   ```

2. **Environment Variables**
   ```bash
   REDIS_URL=redis://:password@hostname:6379/0
   LOG_LEVEL=INFO
   MAX_MESSAGE_AGE=300
   ```

3. **Monitoring**
   - Use Redis INFO command for metrics
   - Monitor memory usage
   - Track message latency
   - Set up alerts for errors

4. **Scaling**
   - Use Redis Cluster for high availability
   - Implement message queuing for high load
   - Consider Redis Sentinel for failover
   - Use connection pooling

## Error Handling

The implementation includes a comprehensive error handling system:

```python
try:
    await agent.send_message(peer_id, message)
except SecurityError as e:
    # Handle security-related errors
    logger.error(f"Security error: {e}")
except ConnectionError as e:
    # Handle connection issues
    logger.error(f"Connection error: {e}")
except Exception as e:
    # Handle unexpected errors
    logger.error(f"Unexpected error: {e}")
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

Apache 2.0

## Security Disclosure

For security issues, please email warchest@dataclysm.xyz or open a private issue. 