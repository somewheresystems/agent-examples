import asyncio
import json
from cryptography.fernet import Fernet
from typing import Dict, Optional, Callable
import websockets
import hashlib
import time

class P2PAgent:
    def __init__(self, agent_id: str, port: int):
        self.agent_id = agent_id
        self.port = port
        self.peers: Dict[str, str] = {}  # agent_id -> websocket_url
        self.message_handlers: Dict[str, Callable] = {}
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.message_buffer = []
        self.max_retries = 3
        self.retry_delay = 1.0  # seconds
        
    async def start(self):
        """Start the agent's websocket server"""
        server = await websockets.serve(self._handle_connection, "localhost", self.port)
        print(f"Agent {self.agent_id} listening on port {self.port}")
        await server.wait_closed()
    
    async def connect_to_peer(self, peer_id: str, peer_url: str):
        """Establish connection with a peer agent"""
        self.peers[peer_id] = peer_url
        # Exchange encryption keys and establish secure channel
        async with websockets.connect(peer_url) as websocket:
            handshake = {
                "type": "handshake",
                "agent_id": self.agent_id,
                "public_key": self.key.decode()
            }
            await websocket.send(json.dumps(handshake))
            response = await websocket.recv()
            print(f"Connected to peer {peer_id}")

    async def send_message(self, peer_id: str, message: dict, retry_count: int = 0):
        """Send encrypted message to a peer with retry mechanism"""
        if peer_id not in self.peers:
            raise ValueError(f"Unknown peer {peer_id}")
            
        try:
            async with websockets.connect(self.peers[peer_id]) as websocket:
                # Encrypt message
                message_json = json.dumps(message)
                encrypted_message = self.cipher_suite.encrypt(message_json.encode())
                
                # Add message metadata
                full_message = {
                    "sender": self.agent_id,
                    "timestamp": time.time(),
                    "message_id": hashlib.sha256(encrypted_message).hexdigest(),
                    "payload": encrypted_message.decode()
                }
                
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
                # Store failed message for later retry
                self.message_buffer.append((peer_id, message))
                raise ConnectionError(f"Failed to send message to {peer_id} after {self.max_retries} retries")

    async def _handle_connection(self, websocket, path):
        """Handle incoming connections and messages"""
        try:
            async for message in websocket:
                data = json.loads(message)
                
                if data["type"] == "handshake":
                    # Handle peer handshake
                    peer_id = data["agent_id"]
                    response = {
                        "type": "handshake_response",
                        "status": "accepted",
                        "agent_id": self.agent_id
                    }
                    await websocket.send(json.dumps(response))
                    
                else:
                    # Decrypt and process regular message
                    try:
                        decrypted_message = self.cipher_suite.decrypt(data["payload"].encode())
                        message_content = json.loads(decrypted_message)
                        
                        # Send acknowledgment
                        ack = {
                            "status": "received",
                            "message_id": data["message_id"]
                        }
                        await websocket.send(json.dumps(ack))
                        
                        # Process message with registered handlers
                        message_type = message_content.get("type")
                        if message_type in self.message_handlers:
                            await self.message_handlers[message_type](message_content)
                            
                    except Exception as e:
                        print(f"Error processing message: {e}")
                        
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")

    def register_handler(self, message_type: str, handler: Callable):
        """Register a message handler for specific message types"""
        self.message_handlers[message_type] = handler

# Example usage
async def main():
    # Create two agents
    agent1 = P2PAgent("agent1", 8001)
    agent2 = P2PAgent("agent2", 8002)
    
    # Start their servers
    await asyncio.gather(
        agent1.start(),
        agent2.start()
    )
    
    # Connect them
    await agent1.connect_to_peer("agent2", "ws://localhost:8002")
    await agent2.connect_to_peer("agent1", "ws://localhost:8001")
    
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