+++
title = "Azure Blob Storage"
chapter = false
weight = 5
+++

## Overview

Azure Blob Storage C2 profile for Mythic with **per-agent container isolation**. Each agent gets its own Azure Blob container with a scoped SAS token, limiting blast radius if an agent is compromised.

### Security Model

- Storage account key **never leaves the Mythic server**
- Each agent receives a container-scoped SAS token (not account-wide)
- Compromised agent cannot access other agents' containers
- Agent cannot: list containers, access other containers, delete blobs

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PAYLOAD BUILD TIME                          │
├─────────────────────────────────────────────────────────────────────┤
│  PayloadType.build():                                               │
│    1. Create container: agent-{uuid[:12]}                          │
│    2. Generate container-scoped SAS token                          │
│    3. Stamp into agent (NOT the account key)                       │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                           RUNTIME                                   │
├─────────────────────────────────────────────────────────────────────┤
│  AGENT (container-scoped SAS only)                                 │
│    ├─► Write: /{container}/checkin.blob                            │
│    ├─► Read:  /{container}/tasking/pending.blob                    │
│    └─► Write: /{container}/response/{task_id}.blob                 │
│                                                                     │
│  C2 SERVER (has account key)                                       │
│    ├─► ListContainers (prefix: agent-)                             │
│    └─► For each container: read/write/delete blobs                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Setup

### 1. Create Azure Storage Account

1. Go to Azure Portal → Storage Accounts → Create
2. Choose a unique name (e.g., `mythicc2storage`)
3. Select region, performance tier (Standard is fine), redundancy (LRS)
4. Create the storage account

### 2. Get Account Key

1. Go to your Storage Account → Access keys
2. Copy **Key1** or **Key2** (either works)
3. Keep this secure - it provides full access to the storage account

### 3. Configure Mythic C2 Profile

When building a payload, provide:

| Parameter | Description |
|-----------|-------------|
| `storage_account` | Your storage account name (e.g., `mythicc2storage`) |
| `account_key` | Storage account key (never sent to agent) |
| `callback_interval` | Polling interval in seconds (default: 30) |
| `callback_jitter` | Jitter percentage (default: 10) |

### 4. PayloadType Integration

Your agent's `builder.py` must provision the container during build:

```python
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions
from datetime import datetime, timedelta

# In your build() function:
container_name = f"agent-{self.uuid[:12].lower()}"

# Create container
connection_string = f"DefaultEndpointsProtocol=https;AccountName={storage_account};AccountKey={account_key};EndpointSuffix=core.windows.net"
blob_service = BlobServiceClient.from_connection_string(connection_string)
blob_service.create_container(container_name)

# Generate container-scoped SAS
sas_token = generate_container_sas(
    account_name=storage_account,
    container_name=container_name,
    account_key=account_key,
    permission=ContainerSasPermissions(read=True, write=True, list=True, add=True, create=True),
    expiry=datetime.utcnow() + timedelta(days=365),
)

# Stamp into agent: storage_account, container_name, sas_token
# DO NOT stamp account_key
```

## Blob Structure

Each agent container uses this structure:

```
agent-{uuid[:12]}/
├── checkin.blob              # Initial checkin (agent writes)
├── tasking/
│   └── pending.blob          # Current tasking (server writes, agent reads)
└── response/
    └── {task_id}.blob        # Task responses (agent writes, server deletes)
```

## Agent Communication

### Initial Checkin
```
PUT /{container}/checkin.blob?{sas_token}
x-ms-blob-type: BlockBlob
Body: <encrypted checkin message>
```

### Get Tasking
```
GET /{container}/tasking/pending.blob?{sas_token}
```

### Post Response
```
PUT /{container}/response/{task_id}.blob?{sas_token}
x-ms-blob-type: BlockBlob
Body: <encrypted response>
```

## Comparison with LokiC2

| Capability | LokiC2 (Account SAS) | This Design (Container SAS) |
|------------|---------------------|------------------------------|
| List all containers | Yes | No |
| Access other agents | Yes | No |
| Inject commands to others | Yes | No |
| Delete other agents' data | Yes | No |
| Blast radius | Entire operation | Single agent |

## Troubleshooting

### Server not seeing agents
- Verify storage account name and key are correct
- Check that containers are being created with `agent-` prefix
- Ensure Mythic can reach Azure (no firewall blocking)

### Agent cannot upload
- Verify SAS token has write permissions
- Check SAS token expiry date
- Ensure container exists

### Permission errors
- Agent should have: read, write, list, add, create
- Agent should NOT have: delete (server handles cleanup)
