import socket
import struct
import threading
import time
from typing import Optional, Tuple
import os
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes  # Add this import

import protocol

# SOCKS5 Constants
VERSION5 = 0x05

# Authentication methods
NO_AUTH = 0x00
GSSAPI = 0x01
USERNAME_PASSWORD = 0x02
NO_ACCEPTABLE_METHODS = 0xFF

# SOCKS5 Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes
REPLY_SUCCESS = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_CONNECTION_NOT_ALLOWED = 0x02
REPLY_NETWORK_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONNECTION_REFUSED = 0x05
REPLY_TTL_EXPIRED = 0x06
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


# === Crypto Functions (keep these as-is from before) ===

def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate X25519 key pair for key exchange"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key.private_bytes_raw(), public_key.public_bytes_raw()


def hkdf_sha3_256(key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF using SHA3-256 (to match Go implementation)"""
    if salt is None or len(salt) == 0:
        salt = bytes(32)
    
    prk = hmac.new(salt, key_material, hashlib.sha3_256).digest()
    
    t = b''
    okm = b''
    i = 0
    
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        okm += t
    
    return okm[:length]


def derive_symmetric_key(private_key: bytes, peer_public_key: bytes, nonce: bytes) -> Tuple[Optional[bytes], int]:
    """Derive symmetric key using X25519 + HKDF-SHA3-256"""
    try:
        print(f"[DEBUG] Key derivation:")
        print(f"[DEBUG]   Nonce (salt, 24 bytes): {nonce.hex()}")
        
        private = x25519.X25519PrivateKey.from_private_bytes(private_key)
        public = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = private.exchange(public)
        
        print(f"[DEBUG]   Shared secret (32 bytes): {shared_secret.hex()}")
        
        symmetric_key = hkdf_sha3_256(
            key_material=shared_secret,
            salt=nonce,
            info=b'',
            length=32
        )
        
        print(f"[DEBUG]   Derived key (32 bytes): {symmetric_key.hex()}")
        
        return symmetric_key, protocol.ErrNone
        
    except Exception as e:
        print(f"[-] Key derivation error: {e}")
        import traceback
        traceback.print_exc()
        return None, protocol.ErrInvalidCrypto


def encrypt_data(key: bytes, plaintext: bytes) -> Tuple[Optional[bytes], int]:
    """
    Encrypt data using XChaCha20-Poly1305 (24-byte nonce)
    
    Format: [nonce (24 bytes)][ciphertext][tag (16 bytes)]
    """
    try:
        # Generate 24-byte nonce (triggers XChaCha20 mode)
        nonce = get_random_bytes(24)  # ← FIXED: Explicit 24-byte nonce
        
        # Create cipher with 24-byte nonce (uses XChaCha20-Poly1305)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)  # ← FIXED: Pass nonce
        
        # Encrypt and get tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Return: nonce + ciphertext + tag
        result = nonce + ciphertext + tag
        
        print(f"[DEBUG] Encrypted {len(plaintext)} bytes -> {len(result)} bytes")
        print(f"[DEBUG]   Nonce: {len(nonce)} bytes (should be 24 for XChaCha20)")
        print(f"[DEBUG]   Ciphertext: {len(ciphertext)} bytes")
        print(f"[DEBUG]   Tag: {len(tag)} bytes (should be 16)")
        
        # Sanity check
        expected_len = 24 + len(plaintext) + 16
        if len(result) != expected_len:
            print(f"[!] WARNING: Expected {expected_len} bytes, got {len(result)}!")
        
        return result, protocol.ErrNone
        
    except Exception as e:
        print(f"[-] Encryption error: {e}")
        import traceback
        traceback.print_exc()
        return None, protocol.ErrInvalidCrypto

def decrypt_data(key: bytes, ciphertext: bytes) -> Tuple[Optional[bytes], int]:
    """Decrypt data using XChaCha20-Poly1305"""
    try:
        if len(ciphertext) < 40:
            print(f"[-] Ciphertext too short: {len(ciphertext)} bytes")
            return None, protocol.ErrInvalidCrypto
        
        nonce = ciphertext[:24]
        ciphertext_and_tag = ciphertext[24:]
        
        actual_ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
        
        print(f"[DEBUG] ✓ Decrypted {len(plaintext)} bytes")
        
        return plaintext, protocol.ErrNone
        
    except ValueError as e:
        print(f"[-] Decryption/verification failed: {e}")
        return None, protocol.ErrInvalidCrypto
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        return None, protocol.ErrInvalidCrypto


# === SOCKS5 Protocol State Machine ===

class Socks5State:
    """SOCKS5 connection states"""
    AUTH_NEGOTIATION = 1    # Waiting for authentication method selection
    AUTH_REQUEST = 2         # Waiting for authentication credentials
    CONNECT_REQUEST = 3      # Waiting for connection request
    CONNECTED = 4            # Connection established, proxying data


def decode_socks5_address(data: bytes) -> Tuple[Optional[str], Optional[int], int, int]:
    """
    Decode SOCKS5 address format
    
    Returns:
        (address, port, bytes_consumed, error_code)
    """
    if len(data) < 2:
        return None, None, 0, protocol.ErrInvalidPacket
    
    atyp = data[0]
    cursor = 1
    
    try:
        if atyp == ATYP_IPV4:
            if len(data) < 1 + 4 + 2:
                return None, None, 0, protocol.ErrInvalidPacket
            
            addr = socket.inet_ntop(socket.AF_INET, data[1:5])
            port = struct.unpack('!H', data[5:7])[0]
            return addr, port, 7, protocol.ErrNone
            
        elif atyp == ATYP_DOMAIN:
            domain_len = data[1]
            if len(data) < 1 + 1 + domain_len + 2:
                return None, None, 0, protocol.ErrInvalidPacket
            
            addr = data[2:2+domain_len].decode('utf-8')
            port = struct.unpack('!H', data[2+domain_len:2+domain_len+2])[0]
            return addr, port, 1 + 1 + domain_len + 2, protocol.ErrNone
            
        elif atyp == ATYP_IPV6:
            if len(data) < 1 + 16 + 2:
                return None, None, 0, protocol.ErrInvalidPacket
            
            addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            port = struct.unpack('!H', data[17:19])[0]
            return addr, port, 19, protocol.ErrNone
            
        else:
            return None, None, 0, protocol.ErrAddressNotSupported
            
    except Exception as e:
        print(f"[DEBUG] Exception during decode: {e}")
        return None, None, 0, protocol.ErrInvalidPacket


def create_socks5_reply(reply_code: int, bind_addr: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    """Create a SOCKS5 reply message"""
    reply = bytearray()
    reply.append(VERSION5)
    reply.append(reply_code)
    reply.append(0x00)
    reply.append(ATYP_IPV4)
    
    addr_parts = bind_addr.split('.')
    for part in addr_parts:
        reply.append(int(part))
    
    reply.extend(struct.pack('!H', bind_port))
    
    return bytes(reply)


def map_error_to_socks_reply(err_code: int) -> int:
    """Map internal error codes to SOCKS5 reply codes"""
    error_map = {
        protocol.ErrNone: REPLY_SUCCESS,
        protocol.ErrNetworkUnreachable: REPLY_NETWORK_UNREACHABLE,
        protocol.ErrHostUnreachable: REPLY_HOST_UNREACHABLE,
        protocol.ErrConnectionRefused: REPLY_CONNECTION_REFUSED,
        protocol.ErrTTLExpired: REPLY_TTL_EXPIRED,
        protocol.ErrUnsupportedCommand: REPLY_COMMAND_NOT_SUPPORTED,
        protocol.ErrAddressNotSupported: REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    }
    return error_map.get(err_code, REPLY_GENERAL_FAILURE)


class SocksHandler:
    """SOCKS5 protocol handler for the agent side"""
    
    def __init__(self, base_handler):
        self.base_handler = base_handler
        self.base_handler.packet_handler = self
        self.active_threads = {}
        
        # Track SOCKS5 state per connection
        self.socks_state = {}  # conn_id -> Socks5State
    
    def on_new(self, conn_id: bytes, data: bytes) -> int:
        """Handle CmdNew - Establish encrypted connection"""
        print(f"[*] OnNew: {conn_id.hex()}")
        
        if self.base_handler.get_connection(conn_id):
            return protocol.ErrConnectionExists
        
        conn = self.base_handler.create_connection(conn_id)
        conn.state = protocol.Connection.STATE_NEW
        
        # Parse key exchange data
        if len(data) != 56:
            print(f"[-] Invalid key exchange data length: {len(data)}")
            self.base_handler.delete_connection(conn_id)
            return protocol.ErrInvalidCrypto
        
        nonce = data[:24]
        server_public_key = data[24:]
        
        print(f"[*] Performing key exchange...")
        
        private_key, public_key = generate_keypair()
        symmetric_key, err_code = derive_symmetric_key(private_key, server_public_key, nonce)
        
        if err_code != protocol.ErrNone:
            print(f"[-] Key derivation failed: {err_code}")
            self.base_handler.delete_connection(conn_id)
            return err_code
        
        conn.secret_key = symmetric_key
        print(f"[+] Key exchange successful")
        
        # Send our public key in CmdAck
        err_code = self.base_handler.send_ack(conn_id, public_key)
        if err_code != protocol.ErrNone:
            print(f"[-] Failed to send ACK: {err_code}")
            self.base_handler.delete_connection(conn_id)
            return err_code
        
        # Initialize SOCKS5 state
        self.socks_state[conn_id] = Socks5State.AUTH_NEGOTIATION
        
        print(f"[+] Connection established, waiting for SOCKS5 handshake...")
        return protocol.ErrNone
    
    def on_ack(self, conn_id: bytes, data: bytes) -> int:
        """Handle CmdAck"""
        return protocol.ErrNone
    
    def on_data(self, conn_id: bytes, data: bytes) -> int:
        """Handle CmdData - Process SOCKS5 protocol"""
        print(f"[*] OnData: {conn_id.hex()} ({len(data)} bytes encrypted)")
        
        conn = self.base_handler.get_connection(conn_id)
        if not conn:
            return protocol.ErrConnectionNotFound
        
        # Decrypt data
        if conn.secret_key:
            decrypted, err_code = decrypt_data(conn.secret_key, data)
            if err_code != protocol.ErrNone:
                print(f"[-] Decryption failed: {err_code}")
                return err_code
            data = decrypted
            print(f"[*] Decrypted to {len(data)} bytes: {data.hex()}")
        
        # Get SOCKS5 state
        state = self.socks_state.get(conn_id, Socks5State.CONNECTED)
        
        # Process based on state
        if state == Socks5State.AUTH_NEGOTIATION:
            return self._handle_auth_negotiation(conn_id, conn, data)
        
        elif state == Socks5State.CONNECT_REQUEST:
            return self._handle_connect_request(conn_id, conn, data)
        
        elif state == Socks5State.CONNECTED:
            # Forward to target
            if conn.socket:
                try:
                    conn.socket.sendall(data)
                    return protocol.ErrNone
                except Exception as e:
                    print(f"[-] Failed to send to target: {e}")
                    self.base_handler.send_close(conn_id, protocol.ErrConnectionClosed)
                    self.base_handler.delete_connection(conn_id)
                    return protocol.ErrConnectionClosed
        
        return protocol.ErrInvalidState
    
    def _handle_auth_negotiation(self, conn_id: bytes, conn, data: bytes) -> int:
        """
        Handle SOCKS5 authentication negotiation
        
        Client sends: [VER][NMETHODS][METHODS...]
        Server replies: [VER][METHOD]
        """
        print(f"[*] SOCKS5 Auth Negotiation")
        
        if len(data) < 2:
            print(f"[-] Auth negotiation data too short")
            return protocol.ErrInvalidPacket
        
        version = data[0]
        nmethods = data[1]
        
        if version != VERSION5:
            print(f"[-] Invalid SOCKS version: {version}")
            return protocol.ErrInvalidSocksVersion
        
        if len(data) < 2 + nmethods:
            print(f"[-] Incomplete auth methods")
            return protocol.ErrInvalidPacket
        
        methods = data[2:2+nmethods]
        print(f"[DEBUG] Client supports methods: {[hex(m) for m in methods]}")
        
        # We only support NO_AUTH
        if NO_AUTH in methods:
            print(f"[+] Selecting NO_AUTH")
            response = bytes([VERSION5, NO_AUTH])
        else:
            print(f"[-] No acceptable auth methods")
            response = bytes([VERSION5, NO_ACCEPTABLE_METHODS])
            
            # Encrypt and send
            if conn.secret_key:
                response, _ = encrypt_data(conn.secret_key, response)
            self.base_handler.send_data(conn_id, response)
            self.base_handler.send_close(conn_id, protocol.ErrAuthFailed)
            self.base_handler.delete_connection(conn_id)
            return protocol.ErrAuthFailed
        
        # Encrypt and send response
        if conn.secret_key:
            response, _ = encrypt_data(conn.secret_key, response)
        
        err_code = self.base_handler.send_data(conn_id, response)
        if err_code != protocol.ErrNone:
            return err_code
        
        # Move to next state
        self.socks_state[conn_id] = Socks5State.CONNECT_REQUEST
        print(f"[+] Auth negotiation complete, waiting for CONNECT request")
        
        return protocol.ErrNone
    
    def _handle_connect_request(self, conn_id: bytes, conn, data: bytes) -> int:
        """
        Handle SOCKS5 CONNECT request
        
        Client sends: [VER][CMD][RSV][ATYP][ADDR][PORT]
        """
        print(f"[*] SOCKS5 CONNECT Request")
        print(f"[DEBUG] Request data: {data.hex()}")
        
        if len(data) < 4:
            print(f"[-] CONNECT request too short")
            return protocol.ErrInvalidPacket
        
        version = data[0]
        cmd = data[1]
        # rsv = data[2]  # Reserved, ignore
        
        if version != VERSION5:
            print(f"[-] Invalid SOCKS version: {version}")
            return protocol.ErrInvalidSocksVersion
        
        if cmd != CMD_CONNECT:
            print(f"[-] Unsupported command: {cmd}")
            reply = create_socks5_reply(REPLY_COMMAND_NOT_SUPPORTED)
            if conn.secret_key:
                reply, _ = encrypt_data(conn.secret_key, reply)
            self.base_handler.send_data(conn_id, reply)
            self.base_handler.send_close(conn_id, protocol.ErrUnsupportedCommand)
            self.base_handler.delete_connection(conn_id)
            return protocol.ErrUnsupportedCommand
        
        # Decode address (starting from byte 3)
        addr, port, bytes_consumed, err_code = decode_socks5_address(data[3:])
        
        if err_code != protocol.ErrNone:
            print(f"[-] Failed to decode address: {err_code}")
            reply = create_socks5_reply(map_error_to_socks_reply(err_code))
            if conn.secret_key:
                reply, _ = encrypt_data(conn.secret_key, reply)
            self.base_handler.send_data(conn_id, reply)
            self.base_handler.send_close(conn_id, err_code)
            self.base_handler.delete_connection(conn_id)
            return err_code
        
        print(f"[*] Connecting to {addr}:{port}")
        
        # Establish connection to target
        try:
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((addr, port))
            target_socket.settimeout(None)
            
            conn.socket = target_socket
            conn.state = protocol.Connection.STATE_CONNECTED
            self.socks_state[conn_id] = Socks5State.CONNECTED
            
            print(f"[+] Connected to {addr}:{port}")
            
            # Send success reply
            reply = create_socks5_reply(REPLY_SUCCESS)
            
            if conn.secret_key:
                encrypted_reply, err_code = encrypt_data(conn.secret_key, reply)
                if err_code != protocol.ErrNone:
                    target_socket.close()
                    self.base_handler.delete_connection(conn_id)
                    return err_code
                reply = encrypted_reply
            
            err_code = self.base_handler.send_data(conn_id, reply)
            if err_code != protocol.ErrNone:
                target_socket.close()
                self.base_handler.delete_connection(conn_id)
                return err_code
            
            # Start receiving from target
            self._start_receive_thread(conn_id, target_socket, conn.secret_key)
            
            return protocol.ErrNone
            
        except socket.timeout:
            err_code = protocol.ErrTTLExpired
        except ConnectionRefusedError:
            err_code = protocol.ErrConnectionRefused
        except socket.gaierror:
            err_code = protocol.ErrHostUnreachable
        except OSError:
            err_code = protocol.ErrNetworkUnreachable
        except Exception as e:
            print(f"[-] Connection error: {e}")
            err_code = protocol.ErrGeneralSocksFailure
        
        # Send error reply
        reply = create_socks5_reply(map_error_to_socks_reply(err_code))
        if conn.secret_key:
            reply, _ = encrypt_data(conn.secret_key, reply)
        
        self.base_handler.send_data(conn_id, reply)
        self.base_handler.delete_connection(conn_id)
        
        return err_code
    
    def on_close(self, conn_id: bytes, reason: int) -> int:
        """Handle CmdClose"""
        print(f"[*] OnClose: {conn_id.hex()} (reason: {reason})")
        
        self.active_threads.pop(conn_id, None)
        self.socks_state.pop(conn_id, None)
        
        return self.base_handler.delete_connection(conn_id)
    
    def _start_receive_thread(self, conn_id: bytes, target_socket: socket.socket, secret_key: bytes):
        """Start thread to receive data from target"""
        def receive_loop():
            print(f"[*] Receive thread started for {conn_id.hex()}")
            try:
                while True:
                    conn = self.base_handler.get_connection(conn_id)
                    if not conn or conn.closed.is_set():
                        break
                    
                    try:
                        data = target_socket.recv(4096)
                    except socket.timeout:
                        continue
                    
                    if not data:
                        print(f"[*] Target closed connection")
                        break
                    
                    print(f"[*] Received {len(data)} bytes from target")
                    
                    if secret_key:
                        encrypted, err_code = encrypt_data(secret_key, data)
                        if err_code != protocol.ErrNone:
                            break
                        data = encrypted
                    
                    err_code = self.base_handler.send_data(conn_id, data)
                    if err_code != protocol.ErrNone:
                        break
                        
            except Exception as e:
                print(f"[-] Receive error: {e}")
            finally:
                self.base_handler.send_close(conn_id, protocol.ErrConnectionClosed)
                self.base_handler.delete_connection(conn_id)
                print(f"[*] Receive thread ended")
        
        thread = threading.Thread(target=receive_loop, daemon=True)
        thread.start()
        self.active_threads[conn_id] = thread