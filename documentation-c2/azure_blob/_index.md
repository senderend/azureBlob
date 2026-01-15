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
│    ├─► Write: /{container}/ats/{message-id}.blob                   │
│    └─► Read:  /{container}/sta/{message-id}.blob                   │
│                                                                     │
│  C2 SERVER (has account key)                                       │
│    ├─► ListContainers (prefix: agent-)                             │
│    ├─► For each: read ats/*, forward to Mythic                     │
│    └─► Write Mythic responses to sta/* with matching message-id    │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Create Azure Storage Account (Azure Portal)

1. Go to **https://portal.azure.com**
2. Create a new **Storage Account**
3. Choose a unique name (e.g., `mythicc2storage123`)
4. Select **Standard** performance, **LRS** redundancy
5. Once created, go to **Access Keys** under Security + networking
6. Save your **storage account name** and **key1**

### 2. Install in Mythic

```bash
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/senderend/azureBlob
```

### 3. Configure via Mythic Web UI

**One-time: Add Azure credentials**
1. Edit `/path/to/Mythic/C2_Profiles/azure_blob/c2_code/config.json`:
   ```json
   {
     "storage_account": "YOUR_STORAGE_ACCOUNT",
     "account_key": "YOUR_ACCOUNT_KEY",
     "poll_interval": 5
   }
   ```
2. Start the C2 profile: `sudo ./mythic-cli c2 start azure_blob`

**Per-payload: Configure C2 instance in GUI**
1. In Mythic web UI, go to **C2 Profiles** → **azure_blob**
2. Create a new profile instance
3. Set parameters:
   - **Callback Interval**: 5 seconds (agent check-in frequency)
   - **Callback Jitter**: 10% (timing variation)
   - **Kill Date**: 28 days from now (SAS token expiration)
4. Click **Start**

### 4. Test with Pegasus

Build a test payload in the web UI:
1. Go to **Payloads** → **Create Payload**
2. Select **pegasus** PayloadType
3. Select your **azure_blob** C2 profile instance
4. Build and run the agent

See `TESTING.md` for complete testing guide.

## Blob Structure

Each agent container uses this structure:

```
agent-{uuid[:12]}/
├── ats/
│   └── {message-id}.blob     # Agent-to-Server messages
└── sta/
    └── {message-id}.blob     # Server-to-Agent responses
```

**Message Format:** All messages are base64-encoded with format: `{36-char-uuid}{json-payload}`

**Message IDs:** Generated per-request for request/response correlation

## Agent Communication

### Message Flow

All agent messages follow the same pattern:

1. **Agent sends request:**
   ```
   PUT /{container}/ats/{message-id}.blob?{sas_token}
   x-ms-blob-type: BlockBlob
   Body: base64({uuid} + json({"action": "...", ...}))
   ```

2. **Agent polls for response:**
   ```
   GET /{container}/sta/{message-id}.blob?{sas_token}
   ```
   Polls until blob exists, then reads and deletes it.

### Message Types

**Checkin:**
```json
{"action": "checkin", "uuid": "...", "ips": [...], "os": "...", ...}
```

**Get Tasking:**
```json
{"action": "get_tasking", "tasking_size": 1}
```

**Post Response:**
```json
{"action": "post_response", "responses": [{...}]}
```

## Pegasus Test Agent

**Pegasus** is a minimal Python agent included in this repository for two purposes:

1. **Testing** - Verify your Azure Blob C2 profile configuration works
2. **Template** - Reference implementation for integrating Azure Blob C2 into your own agents

**Features:**
- Container-scoped SAS token authentication
- UUID-based message correlation
- Built-in commands: shell, whoami, pwd, hostname, exit
- No encryption support (for testing/reference purposes)

**Quick Start:**
```bash
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/senderend/azureBlob
```

See `TESTING.md` for complete setup and testing instructions.

## Integrating into Your Agent

To add Azure Blob C2 support to your own agent, use Pegasus as a reference implementation.

### PayloadType Builder Integration

Your `builder.py` should call the C2 profile's `generate_config` RPC function:

```python
from mythic_container.MythicRPC import SendMythicRPCOtherServiceRPC, MythicRPCOtherServiceRPCMessage

# In your build() function:
config_data = await SendMythicRPCOtherServiceRPC(MythicRPCOtherServiceRPCMessage(
    ServiceName="azure_blob",
    ServiceRPCFunction="generate_config",
    ServiceRPCFunctionArguments={
        "killdate": killdate,  # e.g., "2026-02-01"
        "payload_uuid": self.uuid
    }
))

if config_data.Success:
    blob_endpoint = config_data.Result['blob_endpoint']
    container_name = config_data.Result['container_name']
    sas_token = config_data.Result['sas_token']

    # Stamp these into your agent code
    # NEVER stamp account_key - it stays on the server
else:
    raise Exception(f"Container provisioning failed: {config_data.Error}")
```

**Reference:** `Payload_Type/pegasus/pegasus/agent_functions/builder.py`

### Agent-Side Implementation

Your agent needs to implement the ats/sta messaging pattern:

```python
# 1. Generate unique message ID per request
message_id = uuid.uuid4()

# 2. Send request to ats/ (agent-to-server)
data = base64.b64encode((agent_uuid + json.dumps(message)).encode())
put_blob(f"ats/{message_id}.blob", data)

# 3. Poll for response from sta/ (server-to-agent)
while True:
    response = get_blob(f"sta/{message_id}.blob")
    if response:
        decoded = base64.b64decode(response).decode()
        response_data = json.loads(decoded[36:])  # Skip UUID prefix
        delete_blob(f"sta/{message_id}.blob")
        return response_data
    time.sleep(callback_interval)
```

**Reference:** `Payload_Type/pegasus/pegasus/agent_code/agent.py`

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
- Verify storage account name and key are correct in config.json
- Check that containers are being created with `agent-` prefix
- Ensure Mythic can reach Azure (no firewall blocking)
- Check C2 server logs: `sudo ./mythic-cli logs azure_blob`

### Agent cannot upload
- Verify SAS token has write permissions
- Check SAS token expiry date
- Ensure container exists

### Permission errors
- Agent should have: read, write, list, add, create, delete
- Verify SAS token permissions in generate_config RPC function
- Check SAS token hasn't expired (based on killdate)
