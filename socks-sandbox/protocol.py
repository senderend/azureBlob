import struct
import uuid
import threading
import time
from typing import Optional, Dict, Callable

# Error codes
ErrNone = 0x00
ErrInvalidCommand = 0x01
ErrContextCanceled = 0x02
ErrConnectionClosed = 0x0A
ErrConnectionNotFound = 0x0B
ErrConnectionExists = 0x0C
ErrInvalidState = 0x0D
ErrPacketSendFailed = 0x0E
ErrHandlerStopped = 0x0F
ErrUnexpectedPacket = 0x10
ErrTransportClosed = 0x14
ErrTransportTimeout = 0x15
ErrTransportError = 0x16
ErrInvalidSocksVersion = 0x1E
ErrUnsupportedCommand = 0x1F
ErrHostUnreachable = 0x20
ErrConnectionRefused = 0x21
ErrNetworkUnreachable = 0x22
ErrAddressNotSupported = 0x23
ErrTTLExpired = 0x24
ErrGeneralSocksFailure = 0x25
ErrAuthFailed = 0x26
ErrInvalidPacket = 0x28
ErrInvalidCrypto = 0x29

# Command types
CmdNew = 0x01
CmdAck = 0x02
CmdData = 0x03
CmdClose = 0x04

# Packet structure sizes
COMMAND_SIZE = 1
UUID_SIZE = 16
DATA_LENGTH_SIZE = 4
HEADER_SIZE = COMMAND_SIZE + UUID_SIZE + DATA_LENGTH_SIZE


class Packet:
    """Protocol packet with command, connection ID, and optional data"""
    
    def __init__(self, command: int, connection_id: bytes, data: bytes = b''):
        self.command = command
        self.connection_id = connection_id
        self.data = data if data else b''
    
    def encode(self) -> Optional[bytes]:
        """Encode packet to bytes"""
        try:
            # Command (1 byte)
            result = struct.pack('B', self.command)
            
            # Connection ID (16 bytes)
            result += self.connection_id
            
            # Data length (4 bytes, big-endian)
            result += struct.pack('!I', len(self.data))
            
            # Data (variable length)
            if self.data:
                result += self.data
            
            return result
        except Exception:
            return None
    
    @staticmethod
    def decode(data: bytes) -> Optional['Packet']:
        """Decode bytes to packet"""
        if not data or len(data) < HEADER_SIZE:
            return None
        
        try:
            # Parse command
            command = data[0]
            if command < CmdNew or command > CmdClose:
                return None
            
            # Parse connection ID (16 bytes UUID)
            connection_id = data[1:17]
            
            # Parse data length
            data_length = struct.unpack('!I', data[17:21])[0]
            
            # Verify we have enough data
            if len(data) < HEADER_SIZE + data_length:
                return None
            
            # Extract payload
            payload = data[21:21+data_length] if data_length > 0 else b''
            
            # DEBUG: Print packet details
            cmd_names = {CmdNew: "CmdNew", CmdAck: "CmdAck", CmdData: "CmdData", CmdClose: "CmdClose"}
            print(f"[DEBUG] Decoded packet: {cmd_names.get(command, f'Unknown({command})')}, "
                f"ConnID={connection_id.hex()[:16]}..., PayloadLen={data_length}")
            if data_length > 0 and data_length <= 100:
                print(f"[DEBUG] Payload (hex): {payload.hex()}")
            
            return Packet(command, connection_id, payload)
        
        except Exception:
            return None
        
        
class Connection:
    """Represents a proxy connection"""
    
    STATE_NEW = 0
    STATE_CONNECTED = 1
    STATE_CLOSED = 2
    
    def __init__(self, conn_id: bytes):
        self.id = conn_id
        self.state = self.STATE_NEW
        self.socket = None
        self.read_buffer = []
        self.closed = threading.Event()
        self.secret_key = None
        self.lock = threading.Lock()
    
    def close(self) -> int:
        """Close the connection"""
        with self.lock:
            if self.state == self.STATE_CLOSED:
                return ErrNone
            
            self.state = self.STATE_CLOSED
            self.closed.set()
            
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
            
            return ErrNone


class BaseHandler:
    """Base handler for protocol operations"""
    
    def __init__(self, transport):
        """Initialize base handler with transport
        
        Args:
            transport: Transport implementation for sending/receiving data
        """
        self.transport = transport
        self.connections: Dict[bytes, Connection] = {}
        self.running = True
        self.lock = threading.Lock()
        self.packet_handler = None  # Will be set by subclass
    
    def stop(self):
        """Stop the handler"""
        self.running = False
        if self.transport:
            self.transport.close()
    
    def get_connection(self, conn_id: bytes) -> Optional[Connection]:
        """Get a connection by ID
        
        Args:
            conn_id: Connection ID bytes
            
        Returns:
            Connection object or None if not found
        """
        with self.lock:
            return self.connections.get(conn_id)
    
    def create_connection(self, conn_id: bytes) -> Connection:
        """Create a new connection
        
        Args:
            conn_id: Connection ID bytes
            
        Returns:
            New Connection object
        """
        with self.lock:
            conn = Connection(conn_id)
            self.connections[conn_id] = conn
            return conn
    
    def delete_connection(self, conn_id: bytes) -> int:
        """Delete a connection
        
        Args:
            conn_id: Connection ID bytes
            
        Returns:
            Error code
        """
        with self.lock:
            conn = self.connections.pop(conn_id, None)
            if conn:
                conn.close()
                return ErrNone
            return ErrConnectionNotFound
    
    def close_all_connections(self):
        """Close all active connections"""
        with self.lock:
            for conn in self.connections.values():
                conn.close()
            self.connections.clear()
    
    def send_packet(self, packet: Packet) -> int:
        """Send a packet through the transport"""
        if not self.running:
            return ErrHandlerStopped
        
        if not packet:
            return ErrInvalidPacket
        
        encoded = packet.encode()
        if not encoded:
            return ErrInvalidPacket
        
        return self.transport.send(encoded)
    
    def send_new_connection(self, connection_id: bytes) -> int:
        """Send a new connection packet"""
        # For now, just send empty data
        # In full implementation, would include key exchange
        return self.send_packet(Packet(CmdNew, connection_id, b''))
    
    def send_ack(self, connection_id: bytes, data: bytes = b'') -> int:
        """Send an acknowledgment packet"""
        return self.send_packet(Packet(CmdAck, connection_id, data))
    
    def send_data(self, connection_id: bytes, data: bytes) -> int:
        """Send a data packet"""
        return self.send_packet(Packet(CmdData, connection_id, data))
    
    def send_close(self, connection_id: bytes, err_code: int) -> int:
        """Send a close packet"""
        with self.lock:
            conn = self.connections.get(connection_id)
            if conn:
                conn.close()
        
        return self.send_packet(Packet(CmdClose, connection_id, bytes([err_code])))
    
    def handle_packet(self, packet: Packet) -> int:
        """Route packet to appropriate handler"""
        if not self.packet_handler:
            return ErrInvalidCommand
        
        # DEBUG: Print raw packet bytes
        encoded = packet.encode()
        if encoded:
            print(f"[DEBUG] Handling packet bytes ({len(encoded)} bytes):")
            print(f"[DEBUG] Command: 0x{packet.command:02x}")
            print(f"[DEBUG] ConnID: {packet.connection_id.hex()}")
            print(f"[DEBUG] Data length: {len(packet.data)}")
            if len(packet.data) > 0:
                preview = packet.data[:64].hex() if len(packet.data) > 64 else packet.data.hex()
                print(f"[DEBUG] Data preview: {preview}")
        
        if packet.command == CmdNew:
            return self.packet_handler.on_new(packet.connection_id, packet.data)
        elif packet.command == CmdAck:
            return self.packet_handler.on_ack(packet.connection_id, packet.data)
        elif packet.command == CmdData:
            return self.packet_handler.on_data(packet.connection_id, packet.data)
        elif packet.command == CmdClose:
            reason = packet.data[0] if packet.data else 0
            return self.packet_handler.on_close(packet.connection_id, reason)
        else:
            return ErrInvalidCommand
        
        
    def receive_loop(self):
        """Main receive loop"""
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        print("[*] Starting receive loop...")
        
        while self.running and consecutive_errors < max_consecutive_errors:
            # Receive data from transport
            data, err_code = self.transport.receive()
            
            if err_code != ErrNone:
                consecutive_errors += 1
                if err_code == ErrTransportClosed:
                    print("[-] Transport closed")
                    self.stop()
                    break
                
                # Exponential backoff
                time.sleep(consecutive_errors * 0.05)
                continue
            
            # Reset error counter on success
            consecutive_errors = 0
            
            # Skip empty data
            if not data or len(data) == 0:
                time.sleep(0.1)
                continue
            
            # Decode packet
            packet = Packet.decode(data)
            if not packet:
                print("[-] Failed to decode packet")
                continue
            
            # Handle packet
            result = self.handle_packet(packet)
            if result != ErrNone:
                print(f"[-] Packet handling error: {result}")
        
        if consecutive_errors >= max_consecutive_errors:
            print("[-] Too many consecutive errors, stopping")
        
        print("[*] Receive loop stopped")
        self.close_all_connections()