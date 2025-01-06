# Quantum-Resistant SQS Messaging Protocol

A production-ready implementation of a quantum-resistant messaging protocol using Amazon SQS as the transport layer. This implementation provides secure, authenticated, and encrypted communication between agents, resistant to both classical and quantum attacks.

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
  - Automatic peer discovery via SQS queues
  - Connection timeouts
  - Graceful shutdown
  - Connection retries
- **Message Handling**
  - Long polling for efficient message retrieval
  - Message visibility timeout
  - Message deduplication
  - Type-safe message handling
  - Automatic message deletion after processing

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
  - Proper queue cleanup
- **Error Handling**
  - Comprehensive exception hierarchy
  - Detailed error messages
  - Graceful error recovery
  - AWS error handling
  - Connection error handling

## Requirements

- Python 3.7+
- AWS Account with SQS access
- Required Python packages:
  ```
  aioboto3>=9.0.0
  boto3>=1.26.0
  cryptography>=41.0.0
  python3-liboqs>=0.8.0
  ```

## Installation

1. Install the required dependencies:
   ```bash
   pip install aioboto3 boto3 cryptography python3-liboqs
   ```

2. Configure AWS credentials:
   ```bash
   aws configure
   ```
   Or set environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=your_region
   ```

## Usage

### Basic Example

```python
import asyncio
from networking.sqs.agent_sqs import SQSAgent, Message

async def main():
    # Create agents
    agent1 = SQSAgent("agent1", "us-west-2")
    agent2 = SQSAgent("agent2", "us-west-2")
    
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
async def broadcast(agent: SQSAgent, peers: List[str], message: Message):
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

3. **AWS Security**
   - Use IAM roles with least privilege
   - Enable SQS encryption at rest
   - Use VPC endpoints for SQS
   - Enable CloudTrail logging
   - Set up proper queue permissions

## Production Deployment

1. **AWS Configuration**
   ```python
   # Additional SQS queue attributes for production
   queue_attributes = {
       'MessageRetentionPeriod': '345600',  # 4 days
       'VisibilityTimeout': '30',
       'ReceiveMessageWaitTimeSeconds': '20',
       'KmsMasterKeyId': 'alias/aws/sqs',  # Server-side encryption
       'Policy': {
           # Proper IAM policies
       }
   }
   ```

2. **Environment Variables**
   ```bash
   AWS_REGION=us-west-2
   AWS_PROFILE=production
   LOG_LEVEL=INFO
   MAX_MESSAGE_AGE=300
   VISIBILITY_TIMEOUT=30
   LONG_POLLING_TIME=20
   ```

3. **Monitoring**
   - Use CloudWatch metrics
   - Set up alarms for:
     - Queue depth
     - Message age
     - Error rates
     - Delivery delays
   - Enable X-Ray tracing

4. **Scaling**
   - Use multiple queues for high throughput
   - Implement message batching
   - Use SQS FIFO queues for ordering
   - Implement dead-letter queues
   - Use auto-scaling for consumers

## Error Handling

The implementation includes a comprehensive error handling system:

```python
try:
    await agent.send_message(peer_id, message)
except SecurityError as e:
    # Handle security-related errors
    logger.error(f"Security error: {e}")
except ClientError as e:
    # Handle AWS-specific errors
    logger.error(f"AWS error: {e}")
except Exception as e:
    # Handle unexpected errors
    logger.error(f"Unexpected error: {e}")
```

## AWS Cost Considerations

1. **SQS Pricing**
   - Standard queues: $0.40 per million requests
   - FIFO queues: $0.50 per million requests
   - Data transfer costs apply

2. **Optimization Tips**
   - Use long polling to reduce costs
   - Batch messages when possible
   - Clean up unused queues
   - Monitor queue metrics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

Apache 2.0

## Security Disclosure

For security issues, please email warchest@dataclysm.xyz or open a private issue. 