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

## Pegasus Test Agent

This repository includes **Pegasus**, a minimal Python agent that serves two purposes:

1. **Test the Azure Blob C2 profile** - Verify your C2 configuration works correctly
2. **Template for integration** - Reference implementation showing how to integrate Azure Blob C2 into your own agents

### Features
- Container-scoped SAS token authentication
- UUID-based message correlation (ats/sta blob structure)
- Built-in commands: shell, whoami, pwd, hostname, exit
- No encryption support (for testing/reference purposes)

### Quick Start

See `TESTING.md` for complete setup guide. Key steps:

1. Install C2 profile and Pegasus PayloadType
2. Configure Azure credentials in Mythic web UI
3. Build a payload through the GUI
4. Run and interact with your agent

### Using Pegasus as a Template

To integrate Azure Blob C2 into your own agent:

1. Review `Payload_Type/pegasus/pegasus/agent_functions/builder.py` for PayloadType integration
2. Review `Payload_Type/pegasus/pegasus/agent_code/agent.py` for agent-side implementation
3. Implement the RPC call to `generate_config` in your builder
4. Implement the ats/sta messaging pattern in your agent code

See `documentation-c2/azure_blob/_index.md` for detailed integration guide.

## Development

The C2 server code is located in `C2_Profiles/azure_blob/azure_blob/c2_code/`
