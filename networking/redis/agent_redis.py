import asyncio
import json
import time
import logging
from typing import Dict, Optional, Callable, Any
import redis.asyncio as redis
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

class RedisAgent:
    def __init__(self, agent_id: str, redis_url: str, max_message_age: int = 300):
        """Initialize a quantum-resistant Redis agent
        
        Args:
            agent_id: Unique identifier for this agent
            redis_url: Redis connection URL (e.g. redis://localhost:6379)
            max_message_age: Maximum age of messages in seconds (default: 5 minutes)
        """
        if not agent_id or not isinstance(agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
            
        self.agent_id = agent_id
        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None
        self.peers: Dict[str, dict] = {}
        self.message_handlers: Dict[str, Callable] = {}
        self.max_message_age = max_message_age
        self._processed_messages = set()  # For deduplication
        self._is_running = False
        self._cleanup_task = None
        
        # Post-quantum and classical keys
        self._init_crypto()
        
        # Channels
        self.handshake_channel = f"agents:handshake:{agent_id}"
        self.message_channel_prefix = "agents:messages:"
        
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
    async def connection(self):
        """Context manager for Redis connection"""
        try:
            self.redis = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
                retry_on_timeout=True
            )
            yield self.redis
        finally:
            if self.redis:
                await self.redis.close()
                self.redis = None
    
    async def start(self):
        """Start the Redis agent and subscribe to relevant channels"""
        if self._is_running:
            raise RuntimeError("Agent is already running")
            
        self._is_running = True
        
        async with self.connection() as redis:
            # Publish agent presence and public keys
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
            
            # Publish to handshake channel
            await redis.publish(self.handshake_channel, json.dumps(presence))
            await redis.set(
                f"agents:presence:{self.agent_id}",
                json.dumps(presence),
                ex=self.max_message_age
            )
            
            # Subscribe to channels
            pubsub = redis.pubsub()
            await pubsub.subscribe(self.handshake_channel)
            await pubsub.subscribe(f"{self.message_channel_prefix}{self.agent_id}")
            
            # Start background tasks
            self._cleanup_task = asyncio.create_task(self._cleanup_old_messages())
            message_handler = asyncio.create_task(self._handle_messages(pubsub))
            
            logger.info(f"Agent {self.agent_id} started and listening on Redis")
            
            try:
                await message_handler
            except asyncio.CancelledError:
                logger.info("Shutting down message handler")
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
        if self.redis:
            await self.redis.delete(f"agents:presence:{self.agent_id}")
            await self.redis.close()
    
    async def connect_to_peer(self, peer_id: str, timeout: float = 30.0):
        """Establish quantum-resistant secure connection with a peer"""
        if peer_id == self.agent_id:
            raise ValueError("Cannot connect to self")
        
        try:
            start_time = time.time()
            presence = None
            
            # Wait for peer presence with timeout
            while time.time() - start_time < timeout:
                presence = await self.redis.get(f"agents:presence:{peer_id}")
                if presence:
                    break
                await asyncio.sleep(1)
            
            if not presence:
                raise TimeoutError(f"Peer {peer_id} not found after {timeout} seconds")
            
            presence_data = json.loads(presence)
            
            # Verify message freshness
            if time.time() - presence_data["timestamp"] > self.max_message_age:
                raise SecurityError("Peer presence message is too old")
            
            # Verify peer's signature
            peer_verify_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(presence_data["verify_key"])
            )
            
            # Remove signature for verification
            sig = bytes.fromhex(presence_data.pop("signature"))
            peer_verify_key.verify(sig, json.dumps(presence_data).encode())
            
            # Perform Kyber key encapsulation
            peer_kyber_key = bytes.fromhex(presence_data["kyber_public_key"])
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
                "last_seen": time.time()
            }
            
            logger.info(f"Securely connected to peer {peer_id} with quantum-resistant encryption")
            
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
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
            
            # Publish to peer's message channel
            channel = f"{self.message_channel_prefix}{peer_id}"
            await self.redis.publish(channel, json.dumps(full_message))
            
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            raise
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a handler function for a specific message type"""
        if not callable(handler):
            raise ValueError("Handler must be callable")
        self.message_handlers[message_type] = handler
    
    async def _handle_messages(self, pubsub):
        """Handle incoming Redis messages"""
        while self._is_running:
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True)
                if message is None:
                    await asyncio.sleep(0.01)
                    continue
                
                # Parse message
                data = json.loads(message["data"])
                
                # Verify message freshness
                if time.time() - data["timestamp"] > self.max_message_age:
                    logger.warning("Received outdated message, ignoring")
                    continue
                
                # Check for duplicate messages
                if data.get("message_id") in self._processed_messages:
                    continue
                
                if message["channel"].decode() == self.handshake_channel:
                    await self._handle_handshake(data)
                else:
                    await self._handle_peer_message(data)
                    
                # Mark message as processed
                if "message_id" in data:
                    self._processed_messages.add(data["message_id"])
                    
            except Exception as e:
                logger.error(f"Error handling message: {str(e)}")
    
    async def _handle_handshake(self, handshake_data: dict):
        """Handle peer handshake messages"""
        try:
            peer_id = handshake_data["agent_id"]
            if peer_id == self.agent_id:
                return
            
            # Store presence information
            await self.redis.set(
                f"agents:presence:{peer_id}",
                json.dumps(handshake_data),
                ex=self.max_message_age
            )
            
        except Exception as e:
            logger.error(f"Error handling handshake: {str(e)}")
    
    async def _handle_peer_message(self, message_data: dict):
        """Handle encrypted peer messages"""
        try:
            peer_id = message_data["sender"]
            if peer_id not in self.peers:
                logger.warning(f"Message from unknown peer {peer_id}")
                return
            
            # Verify message is intended for us
            if message_data.get("recipient") != self.agent_id:
                return
            
            # Verify message signature
            sig = base64.b64decode(message_data.pop("signature"))
            self.peers[peer_id]["verify_key"].verify(
                sig,
                json.dumps(message_data).encode()
            )
            
            # Decrypt message
            nonce = base64.b64decode(message_data["nonce"])
            cipher = ChaCha20Poly1305(self.session_keys[peer_id]["key"])
            decrypted_message = cipher.decrypt(
                nonce,
                base64.b64decode(message_data["payload"]),
                peer_id.encode()
            )
            
            # Parse and handle message
            message_content = json.loads(decrypted_message.decode())
            message_type = message_content.get("type")
            
            if message_type in self.message_handlers:
                await self.message_handlers[message_type](Message(**message_content))
            
            # Update peer's last seen timestamp
            self.peers[peer_id]["last_seen"] = time.time()
            
        except Exception as e:
            logger.error(f"Error handling peer message: {str(e)}")
            raise

# Example usage
async def main():
    """Example of how to use the RedisAgent class"""
    # Create two quantum-resistant agents
    agent1 = RedisAgent("agent1", "redis://localhost:6379")
    agent2 = RedisAgent("agent2", "redis://localhost:6379")
    
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