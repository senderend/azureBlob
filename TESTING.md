# Azure Blob C2 - Testing Guide with Pegasus

## Overview

This guide walks through testing the Azure Blob C2 profile using **Pegasus**, a minimal test agent included in this repository.

**Pegasus Purpose:**
- Test the Azure Blob C2 profile configuration
- Serve as a reference implementation for integrating Azure Blob C2 into your own agents
- Demonstrate container isolation and SAS token security model

## Prerequisites

- Running Mythic instance (v3.0+)
- Azure Storage Account with access key
- Python 3.11+

## Step 1: Set Up Azure Storage Account

### Azure Portal Method (Recommended)

1. Go to **https://portal.azure.com** and sign in
2. Click **Create a resource** → **Storage account**
3. Fill in the basics:
   - **Resource group**: Create new or use existing
   - **Storage account name**: Choose a globally unique name (e.g., `mythicc2storage123`)
   - **Region**: Choose one close to your Mythic server
   - **Performance**: Standard (or Premium with Block Blobs for production use)
   - **Redundancy**: Locally-redundant storage (LRS)
4. Click **Review + create** → **Create**
5. Once deployed, go to your storage account
6. In the left menu, under **Security + networking**, click **Access keys**
7. Copy and save these values (keep them secure!):
   - **Storage account name** (e.g., `mythicc2storage123`)
   - **key1** (or key2) - the long access key string

### Alternative: Azure CLI

For automation or if you prefer CLI:

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

---

## Step 2: Install Components into Mythic

### Install from GitHub (Recommended)

```bash
# Navigate to your Mythic installation
cd /path/to/Mythic

# Install both C2 profile and Pegasus PayloadType
sudo ./mythic-cli install github https://github.com/senderend/azureBlob
```

This installs:
- Azure Blob C2 profile
- Pegasus test agent PayloadType

### Alternative: Install from Local Directory

If you've cloned the repository locally:

```bash
# Navigate to your Mythic installation
cd /path/to/Mythic

# Install C2 Profile
sudo ./mythic-cli install folder /path/to/azureBlob/C2_Profiles/azure_blob

# Install PayloadType
sudo ./mythic-cli install folder /path/to/azureBlob/Payload_Type/pegasus
```

---

## Step 3: Configure C2 Profile in Mythic Web UI

### 1. Add Azure Credentials (One-Time Setup)

First, configure your Azure credentials in the C2 profile's config file:

```bash
cd /path/to/Mythic/C2_Profiles/azure_blob/c2_code
nano config.json
```

Add your Azure storage account credentials:
```json
{
  "storage_account": "YOUR_STORAGE_ACCOUNT",
  "account_key": "YOUR_ACCOUNT_KEY",
  "poll_interval": 5
}
```

Save and start the C2 profile:
```bash
sudo ./mythic-cli c2 start azure_blob
```

### 2. Configure C2 Profile Instance in Web UI

1. Open Mythic web UI at `https://localhost:7443`
2. Navigate to **C2 Profiles**
3. Find **azure_blob** and click on it
4. Click **+ Create New Profile Instance** (or edit existing)
5. Configure the parameters:
   - **Callback Interval**: `5` (seconds between agent check-ins)
   - **Callback Jitter**: `10` (percent variation in timing)
   - **Kill Date**: Select date 28 days out (SAS token expiration)
6. Click **Submit**
7. Click the **Start** button to start the C2 server

---

## Step 4: Start PayloadType

```bash
# Start the payload type container
sudo ./mythic-cli payload start pegasus

# Verify it's running
sudo ./mythic-cli payload status

# Check logs
sudo ./mythic-cli logs pegasus
```

---

## Step 5: Create a Payload

### Web UI Method (Recommended)

1. In Mythic web UI, go to **Payloads** → **Create Payload**

2. **Select Operating System**: Choose your target (Linux, macOS, or Windows)

3. **Select Payload Type**: Choose **pegasus**

4. **Select C2 Profile**: Choose your **azure_blob** profile instance (from Step 3)

5. **Build Parameters**:
   - **Output Type**: `py` (Python script) or `exe` (compiled executable)

6. Click **Build Payload**

7. **Watch the build steps**:
   - ✓ Provisioning Azure Container (creates unique container, generates SAS token)
   - ✓ Stamping Configuration (embeds endpoint, interval, jitter)
   - ✓ Finalizing Payload

8. **Download** the generated payload

**Note:** The C2 profile parameters (callback_interval, callback_jitter, killdate) are inherited from your C2 profile instance.

### Alternative: API Method

For automation or scripting, you can create payloads via API:

```bash
# Get your API token from Mythic UI > Settings

curl -X POST https://localhost:7443/api/v1.4/payloads/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "payload_type": "pegasus",
    "c2_profiles": [{
      "c2_profile": "azure_blob",
      "c2_profile_parameters": {
        "callback_interval": "5",
        "callback_jitter": "10",
        "killdate": "2026-01-20"
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
[*] checking for sta/f500bdc6-9c2e-41c0-8a59-10a1e3cf0119.blob: b'...'
[*] Received sta message: {'id': '...', 'status': 'success', 'action': 'checkin'}
[+] new UUID: 12b28168-f474-4f17-b522-9991a0eb831f
[*] starting main loop
```

### Expected Output (Mythic C2 Server Logs)

```
[*] Azure Blob Storage C2 Server started
[*] Storage Account: mythicc2storage
[*] Mythic Address: http://127.0.0.1:17443/agent_message
[*] Poll Interval: 5s
[+] Discovered new agent container: agent-abc123def456
[*] blob name: ats/f500bdc6-9c2e-41c0-8a59-10a1e3cf0119.blob
[*] mythic message: 097e4be2-a789...{"action":"checkin",...}
[*] mythic response: 097e4be2-a789...{"id":"...","status":"success","action":"checkin"}
[*] writing response to: sta/f500bdc6-9c2e-41c0-8a59-10a1e3cf0119.blob
[+] Processed response from agent-abc123def456: ats/f500bdc6-9c2e-41c0-8a59-10a1e3cf0119.blob
```

---

## Step 7: Interact with Agent in Web UI

1. In Mythic web UI, go to **Active Callbacks**
2. You should see your Pegasus agent listed with:
   - Hostname
   - User
   - IP address
   - Operating system
3. Click on the callback to open the **Interact** tab
4. Try the built-in commands:
   ```
   whoami       # Show current user and hostname
   pwd          # Show current directory
   hostname     # Show hostname
   shell ls -la # Execute shell command
   exit         # Terminate the agent
   ```

The agent will poll every 5 seconds (±10% jitter) for new tasks and execute them.

---

## Troubleshooting

### C2 Profile Won't Start

**Via Web UI:**
1. Go to **C2 Profiles** → **azure_blob**
2. Check the **Status** indicator
3. View logs in the **Logs** tab

**Via CLI:**
```bash
# Check logs
sudo ./mythic-cli logs azure_blob
```

**Common issues:**
- Missing storage_account or account_key in config.json
- Azure credentials invalid
- config.json not properly formatted (check JSON syntax)

### Payload Build Fails

**Via Web UI:**
1. Go to **Payloads** → **Created Payloads**
2. Find your failed payload build
3. Click to view build logs and error messages

**Via CLI:**
```bash
# Check payload type logs
sudo ./mythic-cli logs pegasus
```

**Common issues:**
- Can't connect to Azure (network/firewall blocking outbound HTTPS)
- Invalid storage account credentials in config.json
- Container creation failed (check Azure permissions)

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

1. **Check callback in Web UI**: Go to **Active Callbacks** - agent should be listed
2. **View C2 logs**: **C2 Profiles** → **azure_blob** → **Logs** tab - look for forwarding errors
3. **Check agent logs**: Agent should show polling messages like `[*] checking for sta/{message-id}.blob`
4. **Issue a command**: Try `whoami` command - if it times out, check C2 server connectivity

---

## Verification Checklist

- [ ] Azure Storage Account created
- [ ] config.json configured with storage_account and account_key
- [ ] C2 Profile installed and running
- [ ] PayloadType (Pegasus) installed and running
- [ ] Payload builds successfully with Azure container provisioning
- [ ] Container created in Azure (check Azure Portal or logs)
- [ ] Agent runs and writes ats/{message-id}.blob
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
sudo ./mythic-cli payload stop pegasus
```
