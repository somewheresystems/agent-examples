import asyncio
import json
import time
import logging
from typing import Dict, Optional, Callable, Any
import boto3
import aioboto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from oqs import KeyEncapsulation
import secrets
import base64
from dataclasses import dataclass, asdict
import uuid
import os
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Message:
    """Structured message format for type safety and validation"""
    type: str
    content: Any
    message_id: str = None
    timestamp: float = None
    
    def __post_init__(self):
        self.message_id = self.message_id or str(uuid.uuid4())
        self.timestamp = self.timestamp or time.time()
    
    def to_dict(self):
        return asdict(self)

class SecurityError(Exception):
    """Base class for security-related exceptions"""
    pass

class AuthenticationError(SecurityError):
    """Raised when message authentication fails"""
    pass

class EncryptionError(SecurityError):
    """Raised when encryption/decryption fails"""
    pass

class SQSAgent:
    def __init__(
        self,
        agent_id: str,
        region_name: str,
        max_message_age: int = 300,
        visibility_timeout: int = 30,
        long_polling_time: int = 20
    ):
        """Initialize a quantum-resistant SQS agent
        
        Args:
            agent_id: Unique identifier for this agent
            region_name: AWS region name
            max_message_age: Maximum age of messages in seconds (default: 5 minutes)
            visibility_timeout: SQS visibility timeout in seconds (default: 30)
            long_polling_time: SQS long polling wait time in seconds (default: 20)
        """
        if not agent_id or not isinstance(agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
            
        self.agent_id = agent_id
        self.region_name = region_name
        self.max_message_age = max_message_age
        self.visibility_timeout = visibility_timeout
        self.long_polling_time = long_polling_time
        
        self.peers: Dict[str, dict] = {}
        self.message_handlers: Dict[str, Callable] = {}
        self._processed_messages = set()  # For deduplication
        self._is_running = False
        self._cleanup_task = None
        self._message_tasks = set()
        
        # Post-quantum and classical keys
        self._init_crypto()
        
        # SQS queue URLs
        self.handshake_queue_url = None
        self.message_queue_url = None
        self.sqs_session = None
        self.sqs_client = None
        
    def _init_crypto(self):
        """Initialize cryptographic keys and components"""
        # Ed25519 for classical signatures
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()
        
        # Kyber for quantum-resistant key exchange
        self.kyber = KeyEncapsulation('Kyber768')
        self.kyber_public_key = self.kyber.generate_keypair()
        
        # Session keys per peer with creation timestamp
        self.session_keys: Dict[str, dict] = {}
        
    def _rotate_session_key(self, peer_id: str):
        """Rotate session key for a peer"""
        if peer_id in self.peers:
            shared_secret = self.kyber.encapsulate(self.peers[peer_id]["kyber_public_key"])
            session_key = self.derive_session_key(shared_secret, peer_id)
            self.session_keys[peer_id] = {
                "key": session_key,
                "created_at": time.time()
            }
            logger.info(f"Rotated session key for peer {peer_id}")
    
    async def _cleanup_old_messages(self):
        """Periodically cleanup old processed messages and rotate keys"""
        while self._is_running:
            try:
                current_time = time.time()
                
                # Cleanup old processed messages
                self._processed_messages = {
                    msg_id for msg_id in self._processed_messages
                    if current_time - float(msg_id.split(':')[0]) < self.max_message_age
                }
                
                # Rotate old session keys
                for peer_id, session_data in list(self.session_keys.items()):
                    if current_time - session_data["created_at"] > self.max_message_age:
                        self._rotate_session_key(peer_id)
                
                await asyncio.sleep(60)  # Run cleanup every minute
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    def derive_session_key(self, shared_secret: bytes, peer_id: str) -> bytes:
        """Derive a session key using HKDF"""
        if not shared_secret or not peer_id:
            raise ValueError("Invalid shared_secret or peer_id")
            
        salt = os.urandom(32)  # Use random salt for each derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"{self.agent_id}:{peer_id}".encode()
        )
        return hkdf.derive(shared_secret)
    
    @asynccontextmanager
    async def sqs_connection(self):
        """Context manager for SQS connection"""
        session = aioboto3.Session()
        async with session.client('sqs', region_name=self.region_name) as sqs:
            self.sqs_client = sqs
            try:
                yield sqs
            finally:
                self.sqs_client = None
    
    async def _create_queues(self):
        """Create required SQS queues if they don't exist"""
        async with self.sqs_connection() as sqs:
            # Create handshake queue
            handshake_queue_name = f"quantum-handshake-{self.agent_id}"
            try:
                response = await sqs.create_queue(
                    QueueName=handshake_queue_name,
                    Attributes={
                        'MessageRetentionPeriod': str(self.max_message_age),
                        'VisibilityTimeout': str(self.visibility_timeout)
                    }
                )
                self.handshake_queue_url = response['QueueUrl']
            except ClientError as e:
                if e.response['Error']['Code'] == 'QueueAlreadyExists':
                    response = await sqs.get_queue_url(QueueName=handshake_queue_name)
                    self.handshake_queue_url = response['QueueUrl']
                else:
                    raise
            
            # Create message queue
            message_queue_name = f"quantum-messages-{self.agent_id}"
            try:
                response = await sqs.create_queue(
                    QueueName=message_queue_name,
                    Attributes={
                        'MessageRetentionPeriod': str(self.max_message_age),
                        'VisibilityTimeout': str(self.visibility_timeout)
                    }
                )
                self.message_queue_url = response['QueueUrl']
            except ClientError as e:
                if e.response['Error']['Code'] == 'QueueAlreadyExists':
                    response = await sqs.get_queue_url(QueueName=message_queue_name)
                    self.message_queue_url = response['QueueUrl']
                else:
                    raise
    
    async def start(self):
        """Start the SQS agent and begin processing messages"""
        if self._is_running:
            raise RuntimeError("Agent is already running")
            
        self._is_running = True
        
        # Create required queues
        await self._create_queues()
        
        # Publish agent presence
        presence = {
            "type": "presence",
            "agent_id": self.agent_id,
            "kyber_public_key": self.kyber_public_key.hex(),
            "verify_key": self.verify_key.public_bytes().hex(),
            "timestamp": time.time()
        }
        
        # Sign the presence message
        signature = self.signing_key.sign(json.dumps(presence).encode())
        presence["signature"] = signature.hex()
        
        async with self.sqs_connection() as sqs:
            # Publish presence message
            await sqs.send_message(
                QueueUrl=self.handshake_queue_url,
                MessageBody=json.dumps(presence),
                MessageAttributes={
                    'MessageType': {
                        'DataType': 'String',
                        'StringValue': 'presence'
                    }
                }
            )
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_old_messages())
        handshake_handler = asyncio.create_task(self._handle_handshake_messages())
        message_handler = asyncio.create_task(self._handle_peer_messages())
        
        logger.info(f"Agent {self.agent_id} started and listening on SQS")
        
        try:
            await asyncio.gather(handshake_handler, message_handler)
        except asyncio.CancelledError:
            logger.info("Shutting down message handlers")
        finally:
            self._is_running = False
            if self._cleanup_task:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass
    
    async def stop(self):
        """Stop the agent gracefully"""
        self._is_running = False
        
        # Cancel all running tasks
        for task in self._message_tasks:
            task.cancel()
        
        # Delete queues
        if self.sqs_client:
            try:
                await self.sqs_client.delete_queue(QueueUrl=self.handshake_queue_url)
                await self.sqs_client.delete_queue(QueueUrl=self.message_queue_url)
            except Exception as e:
                logger.error(f"Error deleting queues: {e}")
    
    async def connect_to_peer(self, peer_id: str, timeout: float = 30.0):
        """Establish quantum-resistant secure connection with a peer"""
        if peer_id == self.agent_id:
            raise ValueError("Cannot connect to self")
        
        try:
            start_time = time.time()
            peer_queue_url = None
            
            # Get peer's handshake queue URL
            async with self.sqs_connection() as sqs:
                while time.time() - start_time < timeout:
                    try:
                        response = await sqs.get_queue_url(
                            QueueName=f"quantum-handshake-{peer_id}"
                        )
                        peer_queue_url = response['QueueUrl']
                        break
                    except ClientError:
                        await asyncio.sleep(1)
                
                if not peer_queue_url:
                    raise TimeoutError(f"Peer {peer_id} not found after {timeout} seconds")
                
                # Send connection request
                request = {
                    "type": "connection_request",
                    "agent_id": self.agent_id,
                    "kyber_public_key": self.kyber_public_key.hex(),
                    "verify_key": self.verify_key.public_bytes().hex(),
                    "timestamp": time.time()
                }
                
                # Sign the request
                signature = self.signing_key.sign(json.dumps(request).encode())
                request["signature"] = signature.hex()
                
                await sqs.send_message(
                    QueueUrl=peer_queue_url,
                    MessageBody=json.dumps(request),
                    MessageAttributes={
                        'MessageType': {
                            'DataType': 'String',
                            'StringValue': 'connection_request'
                        }
                    }
                )
                
                # Wait for connection response
                while time.time() - start_time < timeout:
                    response = await sqs.receive_message(
                        QueueUrl=self.handshake_queue_url,
                        MaxNumberOfMessages=1,
                        WaitTimeSeconds=self.long_polling_time,
                        MessageAttributeNames=['MessageType'],
                        AttributeNames=['All']
                    )
                    
                    if 'Messages' in response:
                        for message in response['Messages']:
                            message_body = json.loads(message['Body'])
                            if (message_body.get('type') == 'connection_response' and
                                message_body.get('responder_id') == peer_id):
                                # Process connection response
                                await self._process_connection_response(message_body)
                                # Delete processed message
                                await sqs.delete_message(
                                    QueueUrl=self.handshake_queue_url,
                                    ReceiptHandle=message['ReceiptHandle']
                                )
                                return
                    
                    await asyncio.sleep(1)
                
                raise TimeoutError("Connection response timeout")
                
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            raise
    
    async def _process_connection_response(self, response_data: dict):
        """Process connection response from peer"""
        try:
            # Verify message freshness
            if time.time() - response_data["timestamp"] > self.max_message_age:
                raise SecurityError("Connection response is too old")
            
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
            peer_id = response_data["responder_id"]
            session_key = self.derive_session_key(shared_secret, peer_id)
            self.session_keys[peer_id] = {
                "key": session_key,
                "created_at": time.time()
            }
            
            # Store peer information
            self.peers[peer_id] = {
                "verify_key": peer_verify_key,
                "kyber_public_key": peer_kyber_key,
                "last_seen": time.time(),
                "queue_url": f"quantum-messages-{peer_id}"
            }
            
            logger.info(f"Securely connected to peer {peer_id} with quantum-resistant encryption")
            
        except Exception as e:
            logger.error(f"Error processing connection response: {str(e)}")
            raise
    
    async def send_message(self, peer_id: str, message: Message):
        """Send encrypted message to a peer with quantum-resistant encryption"""
        if not self._is_running:
            raise RuntimeError("Agent is not running")
            
        if peer_id not in self.peers:
            raise ValueError(f"Unknown peer {peer_id}")
        
        try:
            # Create AEAD cipher with session key
            nonce = secrets.token_bytes(12)
            cipher = ChaCha20Poly1305(self.session_keys[peer_id]["key"])
            
            # Prepare message
            message_dict = message.to_dict()
            message_json = json.dumps(message_dict)
            
            # Encrypt message
            encrypted_message = cipher.encrypt(
                nonce,
                message_json.encode(),
                self.agent_id.encode()
            )
            
            # Create full message with metadata
            full_message = {
                "sender": self.agent_id,
                "recipient": peer_id,
                "timestamp": time.time(),
                "message_id": f"{time.time()}:{uuid.uuid4()}",
                "nonce": base64.b64encode(nonce).decode(),
                "payload": base64.b64encode(encrypted_message).decode()
            }
            
            # Sign the message
            signature = self.signing_key.sign(json.dumps(full_message).encode())
            full_message["signature"] = base64.b64encode(signature).decode()
            
            # Send message to peer's queue
            async with self.sqs_connection() as sqs:
                peer_queue_url = await sqs.get_queue_url(
                    QueueName=self.peers[peer_id]["queue_url"]
                )
                await sqs.send_message(
                    QueueUrl=peer_queue_url['QueueUrl'],
                    MessageBody=json.dumps(full_message),
                    MessageAttributes={
                        'MessageType': {
                            'DataType': 'String',
                            'StringValue': 'encrypted_message'
                        }
                    }
                )
            
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            raise
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a handler function for a specific message type"""
        if not callable(handler):
            raise ValueError("Handler must be callable")
        self.message_handlers[message_type] = handler
    
    async def _handle_handshake_messages(self):
        """Handle incoming handshake messages"""
        while self._is_running:
            try:
                async with self.sqs_connection() as sqs:
                    response = await sqs.receive_message(
                        QueueUrl=self.handshake_queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=self.long_polling_time,
                        MessageAttributeNames=['MessageType'],
                        AttributeNames=['All']
                    )
                    
                    if 'Messages' in response:
                        for message in response['Messages']:
                            try:
                                message_body = json.loads(message['Body'])
                                
                                # Handle different handshake message types
                                if message_body.get('type') == 'connection_request':
                                    await self._handle_connection_request(message_body)
                                
                                # Delete processed message
                                await sqs.delete_message(
                                    QueueUrl=self.handshake_queue_url,
                                    ReceiptHandle=message['ReceiptHandle']
                                )
                                
                            except Exception as e:
                                logger.error(f"Error processing handshake message: {e}")
                    
            except Exception as e:
                logger.error(f"Error in handshake handler: {str(e)}")
                await asyncio.sleep(1)
    
    async def _handle_connection_request(self, request_data: dict):
        """Handle incoming connection request"""
        try:
            peer_id = request_data["agent_id"]
            if peer_id == self.agent_id:
                return
            
            # Verify message freshness
            if time.time() - request_data["timestamp"] > self.max_message_age:
                raise SecurityError("Connection request is too old")
            
            # Verify peer's signature
            peer_verify_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(request_data["verify_key"])
            )
            
            # Remove signature for verification
            sig = bytes.fromhex(request_data.pop("signature"))
            peer_verify_key.verify(sig, json.dumps(request_data).encode())
            
            # Create connection response
            response = {
                "type": "connection_response",
                "responder_id": self.agent_id,
                "kyber_public_key": self.kyber_public_key.hex(),
                "verify_key": self.verify_key.public_bytes().hex(),
                "timestamp": time.time()
            }
            
            # Sign the response
            signature = self.signing_key.sign(json.dumps(response).encode())
            response["signature"] = signature.hex()
            
            # Perform Kyber key encapsulation
            peer_kyber_key = bytes.fromhex(request_data["kyber_public_key"])
            shared_secret = self.kyber.encapsulate(peer_kyber_key)
            
            # Derive session key
            session_key = self.derive_session_key(shared_secret, peer_id)
            self.session_keys[peer_id] = {
                "key": session_key,
                "created_at": time.time()
            }
            
            # Store peer information
            self.peers[peer_id] = {
                "verify_key": peer_verify_key,
                "kyber_public_key": peer_kyber_key,
                "last_seen": time.time(),
                "queue_url": f"quantum-messages-{peer_id}"
            }
            
            # Send response
            async with self.sqs_connection() as sqs:
                peer_queue_url = await sqs.get_queue_url(
                    QueueName=f"quantum-handshake-{peer_id}"
                )
                await sqs.send_message(
                    QueueUrl=peer_queue_url['QueueUrl'],
                    MessageBody=json.dumps(response),
                    MessageAttributes={
                        'MessageType': {
                            'DataType': 'String',
                            'StringValue': 'connection_response'
                        }
                    }
                )
            
            logger.info(f"Accepted connection from peer {peer_id}")
            
        except Exception as e:
            logger.error(f"Error handling connection request: {str(e)}")
            raise
    
    async def _handle_peer_messages(self):
        """Handle incoming peer messages"""
        while self._is_running:
            try:
                async with self.sqs_connection() as sqs:
                    response = await sqs.receive_message(
                        QueueUrl=self.message_queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=self.long_polling_time,
                        MessageAttributeNames=['MessageType'],
                        AttributeNames=['All']
                    )
                    
                    if 'Messages' in response:
                        for message in response['Messages']:
                            task = asyncio.create_task(
                                self._process_peer_message(message, sqs)
                            )
                            self._message_tasks.add(task)
                            task.add_done_callback(self._message_tasks.discard)
                    
            except Exception as e:
                logger.error(f"Error in peer message handler: {str(e)}")
                await asyncio.sleep(1)
    
    async def _process_peer_message(self, message: dict, sqs):
        """Process a single peer message"""
        try:
            message_body = json.loads(message['Body'])
            
            # Check for duplicate messages
            if message_body.get("message_id") in self._processed_messages:
                return
            
            peer_id = message_body["sender"]
            if peer_id not in self.peers:
                logger.warning(f"Message from unknown peer {peer_id}")
                return
            
            # Verify message is intended for us
            if message_body.get("recipient") != self.agent_id:
                return
            
            # Verify message freshness
            if time.time() - message_body["timestamp"] > self.max_message_age:
                logger.warning("Received outdated message, ignoring")
                return
            
            # Verify message signature
            sig = base64.b64decode(message_body.pop("signature"))
            self.peers[peer_id]["verify_key"].verify(
                sig,
                json.dumps(message_body).encode()
            )
            
            # Decrypt message
            nonce = base64.b64decode(message_body["nonce"])
            cipher = ChaCha20Poly1305(self.session_keys[peer_id]["key"])
            decrypted_message = cipher.decrypt(
                nonce,
                base64.b64decode(message_body["payload"]),
                peer_id.encode()
            )
            
            # Parse and handle message
            message_content = json.loads(decrypted_message.decode())
            message_type = message_content.get("type")
            
            if message_type in self.message_handlers:
                await self.message_handlers[message_type](Message(**message_content))
            
            # Update peer's last seen timestamp
            self.peers[peer_id]["last_seen"] = time.time()
            
            # Mark message as processed
            self._processed_messages.add(message_body["message_id"])
            
            # Delete processed message
            await sqs.delete_message(
                QueueUrl=self.message_queue_url,
                ReceiptHandle=message['ReceiptHandle']
            )
            
        except Exception as e:
            logger.error(f"Error processing peer message: {str(e)}")
            raise

# Example usage
async def main():
    """Example of how to use the SQSAgent class"""
    # Create two quantum-resistant agents
    agent1 = SQSAgent("agent1", "us-west-2")
    agent2 = SQSAgent("agent2", "us-west-2")
    
    # Start agents
    task1 = asyncio.create_task(agent1.start())
    task2 = asyncio.create_task(agent2.start())
    
    # Give agents time to start
    await asyncio.sleep(1)
    
    try:
        # Connect them
        await agent1.connect_to_peer("agent2")
        await agent2.connect_to_peer("agent1")
        
        # Define message handlers
        async def handle_query(message: Message):
            logger.info(f"Received query: {message.content}")
            
        agent1.register_handler("query", handle_query)
        agent2.register_handler("query", handle_query)
        
        # Send test message
        await agent1.send_message("agent2", Message(
            type="query",
            content="Hello from agent1!"
        ))
        
        # Keep running
        await asyncio.gather(task1, task2)
        
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        await agent1.stop()
        await agent2.stop()
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
    finally:
        # Cleanup
        for task in asyncio.all_tasks():
            task.cancel()

if __name__ == "__main__":
    asyncio.run(main()) 