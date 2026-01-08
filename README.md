# Azure Blob Storage C2 Profile

A [Mythic](https://github.com/its-a-feature/Mythic) C2 Profile that uses Azure Blob Storage for command and control communication with **per-agent container isolation**.

## Security Model

Unlike other cloud storage C2 approaches that use account-wide credentials, this profile:

- **Never sends the storage account key to agents**
- **Creates a unique container per agent** (`agent-{uuid}`)
- **Generates container-scoped SAS tokens** for each agent
- **Limits blast radius** - compromised agent cannot access other agents

## Installation

```bash
sudo ./mythic-cli install azure_blob https://github.com/senderend/azureBlob
```

## Setup

1. Create an Azure Storage Account
2. Get the storage account key
3. Configure the C2 profile with your storage account name and key
4. Integrate with your PayloadType to provision containers during build

See full documentation at `documentation-c2/azure_blob/_index.md`

## Architecture

```
PAYLOAD BUILD TIME:
  PayloadType.build() creates container + generates scoped SAS token

RUNTIME:
  Agent → writes to its container → Server polls all containers → Mythic
                                 ← writes tasking back ←
```

## Blob Structure

```
agent-{uuid[:12]}/
├── ats/{message-id}.blob     # Agent-to-Server messages (checkin, get_tasking, post_response)
└── sta/{message-id}.blob     # Server-to-Agent responses (tasking, acknowledgments)
```

Messages use UUID-based naming for request/response correlation. Each message is prefixed with the agent's UUID followed by JSON payload.

## Compatible Agents

This C2 profile requires PayloadType integration to provision Azure containers.
See documentation for integration guide.

## Development

The C2 server code is located in `C2_Profiles/azure_blob/azure_blob/c2_code/`
