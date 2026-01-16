+++
title = "Pegasus"
chapter = false
weight = 5
+++

## Overview

Pegasus is a minimal Python agent included with the Azure Blob C2 profile for two purposes:

1. **Testing** - Validate your Azure Blob C2 configuration without additional agent development
2. **Template** - Reference implementation for integrating Azure Blob C2 into your own agents

**Note:** Pegasus does not support encryption and is intended for testing and reference only, not operational use.

## Features

- Container-scoped SAS token authentication
- UUID-based message correlation (ats/sta blob structure)
- Built-in commands: `shell`, `whoami`, `pwd`, `hostname`, `exit`

## Quick Start

```bash
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/senderend/azureBlob
```

This installs both the Azure Blob C2 profile and Pegasus PayloadType.

See `TESTING.md` in the repository for complete setup and testing instructions.

## Build Parameters

| Parameter | Description |
|-----------|-------------|
| Output Type | `py` (Python script) or `exe` (compiled executable) |

C2 parameters (callback interval, jitter, kill date) are inherited from the selected Azure Blob C2 profile instance.

## Commands

| Command | Description |
|---------|-------------|
| `shell <cmd>` | Execute a shell command |
| `whoami` | Show current user |
| `pwd` | Show current working directory |
| `hostname` | Show hostname |
| `exit` | Terminate the agent |

## Using Pegasus as a Template

To integrate Azure Blob C2 into your own agent, review these files:

- **Builder integration:** `Payload_Type/pegasus/pegasus/agent_functions/builder.py`
- **Agent implementation:** `Payload_Type/pegasus/pegasus/agent_code/agent.py`

Key implementation points:

1. Call the `generate_config` RPC function during build to provision the container
2. Stamp the returned values (endpoint, container name, SAS token) into your agent
3. Implement blob PUT/GET/DELETE operations against the ats/ and sta/ paths

See the Azure Blob C2 profile documentation for detailed integration guidance.
