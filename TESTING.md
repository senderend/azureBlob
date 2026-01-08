# Azure Blob C2 - Mythic Integration & Testing Guide

## Prerequisites

- Running Mythic instance (v3.0+)
- Azure Storage Account with access key
- Python 3.11+

## Step 1: Set Up Azure Storage Account

### Option A: Azure CLI

```bash
# Login to Azure
az login

# Create resource group
az group create --name mythic-c2-rg --location eastus

# Create storage account (name must be globally unique)
az storage account create \
  --name mythicc2storage$(date +%s) \
  --resource-group mythic-c2-rg \
  --location eastus \
  --sku Standard_LRS \
  --kind StorageV2 \
  --allow-blob-public-access false

# Get the account name (save this)
STORAGE_ACCOUNT=$(az storage account list --resource-group mythic-c2-rg --query '[0].name' -o tsv)
echo "Storage Account: $STORAGE_ACCOUNT"

# Get account key (save this - keep secret!)
ACCOUNT_KEY=$(az storage account keys list \
  --account-name $STORAGE_ACCOUNT \
  --resource-group mythic-c2-rg \
  --query '[0].value' -o tsv)
echo "Account Key: $ACCOUNT_KEY"
```

### Option B: Azure Portal

1. Go to https://portal.azure.com
2. Create a new **Storage Account**
3. Go to **Access Keys** under Security + networking
4. Copy the **Storage account name** and **key1**

---

## Step 2: Install Components into Mythic

### Install from Local Directory

```bash
# Navigate to your Mythic installation
cd /path/to/Mythic

# Install C2 Profile
sudo ./mythic-cli install folder /path/to/azureBlob/C2_Profiles/azure_blob

# Install PayloadType
sudo ./mythic-cli install folder /path/to/azureBlob/Payload_Type/azure_test_agent
```

### Install from GitHub (after pushing)

```bash
cd /path/to/Mythic

# Install both components
sudo ./mythic-cli install github https://github.com/YOUR_USERNAME/azureBlob
```

---

## Step 3: Configure and Start C2 Profile

### Start the C2 Profile Container

```bash
# Start the azure_blob C2 profile
sudo ./mythic-cli c2 start azure_blob

# Verify it's running
sudo ./mythic-cli c2 status

# Check logs
sudo ./mythic-cli logs azure_blob
```

### Configure C2 Profile in Mythic UI

1. Go to Mythic web UI (https://localhost:7443)
2. Navigate to **C2 Profiles**
3. Click **azure_blob**
4. Click **Configure** (or create new instance)
5. Fill in:
   - **storage_account**: Your Azure storage account name
   - **account_key**: Your Azure storage account key
   - **callback_interval**: 30 (seconds)
   - **callback_jitter**: 10 (percent)
6. Click **Save**
7. Click **Start** to start the C2 profile server

---

## Step 4: Start PayloadType

```bash
# Start the payload type container
sudo ./mythic-cli payload start azure_test_agent

# Verify it's running
sudo ./mythic-cli payload status

# Check logs
sudo ./mythic-cli logs azure_test_agent
```

---

## Step 5: Create a Payload

### Via Mythic UI

1. Go to **Payloads** > **Create Payload**
2. Select OS: **Linux** (or your target)
3. Select Payload Type: **azure_test_agent**
4. Select C2 Profile: **azure_blob**
5. Configure C2 parameters (should auto-fill from profile):
   - Verify storage_account is set
   - Verify account_key is set
6. Click **Create Payload**
7. Wait for build to complete
8. Download the payload

### Via API (curl)

```bash
# Get your API token from Mythic UI > Settings

curl -X POST https://localhost:7443/api/v1.4/payloads/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "payload_type": "azure_test_agent",
    "c2_profiles": [{
      "c2_profile": "azure_blob",
      "c2_profile_parameters": {
        "storage_account": "YOUR_STORAGE_ACCOUNT",
        "account_key": "YOUR_ACCOUNT_KEY",
        "callback_interval": "30",
        "callback_jitter": "10"
      }
    }],
    "selected_os": "linux",
    "filename": "agent.py",
    "build_parameters": [{
      "name": "output_type",
      "value": "py"
    }]
  }'
```

---

## Step 6: Run the Agent

### On Target Machine

```bash
# Download or transfer the payload
# Then run it:
python3 agent.py
```

### Expected Output (Agent Side)

```
[*] Azure Blob Test Agent starting
[*] Endpoint: https://mythicc2storage.blob.core.windows.net
[*] Container: agent-abc123def456
[*] Interval: 30s (jitter: 10%)
[*] Checking in as <uuid>
[+] Checkin blob written
```

### Expected Output (Mythic C2 Server Logs)

```
[*] Azure Blob Storage C2 Server started
[*] Storage Account: mythicc2storage
[+] Discovered new agent container: agent-abc123def456
[+] Processed checkin from agent-abc123def456
```

---

## Step 7: Interact with Agent

1. Go to Mythic UI > **Active Callbacks**
2. You should see your agent listed
3. Click on the agent to open the interaction console
4. Try commands:
   ```
   shell whoami
   shell hostname
   shell pwd
   shell ls -la
   ```

---

## Troubleshooting

### C2 Profile Won't Start

```bash
# Check logs
sudo ./mythic-cli logs azure_blob

# Common issues:
# - Missing storage_account or account_key in config
# - Azure credentials invalid
```

### Payload Build Fails

```bash
# Check payload type logs
sudo ./mythic-cli logs azure_test_agent

# Common issues:
# - Can't connect to Azure (network/firewall)
# - Invalid storage account credentials
# - Container creation failed
```

### Agent Doesn't Check In

1. **Verify Azure credentials**: Test with Azure CLI
   ```bash
   az storage container list --account-name $STORAGE_ACCOUNT --account-key $ACCOUNT_KEY
   ```

2. **Check if container was created**:
   ```bash
   az storage container list \
     --account-name $STORAGE_ACCOUNT \
     --account-key $ACCOUNT_KEY \
     --prefix agent-
   ```

3. **Check blob contents**:
   ```bash
   az storage blob list \
     --container-name agent-XXXX \
     --account-name $STORAGE_ACCOUNT \
     --account-key $ACCOUNT_KEY
   ```

4. **Verify SAS token** (from agent's perspective):
   ```bash
   # Get the SAS URL from the built agent and test it
   curl -I "https://STORAGE.blob.core.windows.net/CONTAINER/checkin.blob?SAS_TOKEN"
   ```

### Agent Checks In But No Tasking

1. Check Mythic server received the checkin (UI shows callback)
2. Check C2 profile logs for forwarding errors
3. Verify Mythic address is correct in C2 config

---

## Verification Checklist

- [ ] Azure Storage Account created
- [ ] C2 Profile installed and running
- [ ] PayloadType installed and running
- [ ] Payload builds successfully
- [ ] Container created in Azure (check Azure Portal)
- [ ] Agent runs and writes checkin.blob
- [ ] Callback appears in Mythic UI
- [ ] Commands execute and return output
- [ ] SAS token is container-scoped (agent can't see other containers)

---

## Security Validation

### Verify Container Isolation

After agent is running, verify it cannot access other containers:

```python
# Test script - run with agent's SAS token
import urllib.request

# Agent's SAS token (extract from built payload)
sas = "YOUR_AGENT_SAS_TOKEN"
storage = "YOUR_STORAGE_ACCOUNT"

# Try to list containers (should fail - 403)
try:
    url = f"https://{storage}.blob.core.windows.net/?comp=list&{sas}"
    urllib.request.urlopen(url)
    print("FAIL: Agent can list containers!")
except urllib.error.HTTPError as e:
    if e.code == 403:
        print("PASS: Agent cannot list containers (403 Forbidden)")
    else:
        print(f"UNEXPECTED: {e}")
```

### Verify Account Key Not in Payload

```bash
# Search for account key in built payload
grep -q "YOUR_ACCOUNT_KEY" agent.py && echo "FAIL: Key found!" || echo "PASS: Key not in payload"
```

---

## Cleanup

### Remove Azure Resources

```bash
# Delete the resource group (removes everything)
az group delete --name mythic-c2-rg --yes --no-wait
```

### Remove from Mythic

```bash
sudo ./mythic-cli c2 stop azure_blob
sudo ./mythic-cli payload stop azure_test_agent
```
