#!/usr/bin/env python3
"""
Azure Blob Storage C2 Server - Polling Loop

Polls Azure Blob Storage for agent messages and forwards them to Mythic.
Uses account key to access all agent containers (agent-* prefix).
"""

import asyncio
import base64
import json
import logging
import os
import sys
from pathlib import Path

import aiohttp
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.WARNING,  # Set root logger to WARNING
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
# Set our logger to INFO, but suppress Azure SDK verbose logging
log.setLevel(logging.INFO)
logging.getLogger('azure').setLevel(logging.WARNING)
logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)


class AzureBlobServer:
    def __init__(self):
        self.storage_account = ""
        self.account_key = ""
        self.mythic_address = os.environ.get("MYTHIC_ADDRESS", "http://127.0.0.1:17443/agent_message")
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
            log.error("Missing storage_account or account_key configuration")
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
                        "Mythic": "azure_blob",
                    },
                    ssl=False,
                ) as resp:
                    return await resp.read()
            except Exception as e:
                log.error(f"Error forwarding to Mythic: {e}")
                return b""

    async def process_messages(self, container_name: str):
        """Process messages"""
        container_client = self.blob_service.get_container_client(container_name)

        try:
            # List response blobs
            blobs = list(container_client.list_blobs(name_starts_with="ats/"))

            for blob in blobs:
                try:
                    blob_client = container_client.get_blob_client(blob.name)
                    data = blob_client.download_blob().readall()
                    blob_client.delete_blob()

                    # Forward to Mythic
                    response = await self.forward_to_mythic(data)
                    if response:
                        response_name = blob.name.replace('ats', 'sta')
                        tasking_blob = container_client.get_blob_client(response_name)
                        tasking_blob.upload_blob(response, overwrite=True)

                except Exception as e:
                    log.error(f"Error processing message {blob.name}: {e}")

        except Exception as e:
            log.error(f"Error listing messages for {container_name}: {e}")

    async def poll_loop(self):
        """Main polling loop"""
        log.info("Azure Blob Storage C2 Server started")
        log.info(f"Storage Account: {self.storage_account}")
        log.info(f"Mythic Address: {self.mythic_address}")
        log.info(f"Poll Interval: {self.poll_interval}s")
        sys.stdout.flush()

        while True:
            try:
                # Discover agent containers
                containers = self.blob_service.list_containers(name_starts_with="agent-")

                for container in containers:
                    container_name = container.name

                    if container_name not in self.known_containers:
                        log.info(f"Discovered new agent container: {container_name}")
                        self.known_containers.add(container_name)
                    # Process messages
                    await self.process_messages(container_name)

            except Exception as e:
                log.error(f"Polling error: {e}")

            sys.stdout.flush()
            await asyncio.sleep(self.poll_interval)

    def run(self):
        """Entry point"""
        self.load_config()
        asyncio.run(self.poll_loop())


if __name__ == "__main__":
    server = AzureBlobServer()
    server.run()
