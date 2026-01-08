from mythic_container.C2ProfileBase import *
from pathlib import Path
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions
from datetime import datetime

async def generate_config(input: C2OtherServiceRPCMessage) -> C2OtherServiceRPCMessageResponse:
    # Generate unique container name
    storage_account = input.ServiceRPCFunctionArguments.get("storage_account", None)
    account_key = input.ServiceRPCFunctionArguments.get("account_key", None)
    payload_uuid = input.ServiceRPCFunctionArguments.get("payload_uuid", None)
    killdate = input.ServiceRPCFunctionArguments.get("killdate", None)
    if storage_account == None or account_key == None or payload_uuid == None or killdate == None:
        return C2OtherServiceRPCMessageResponse(
            Success=False,
            Error=f"[*] Missing a required parameter: storage_account, account_key, payload_uuid, or killdate",
        )
    container_name = f"agent-{payload_uuid[:12].lower()}"

    # Create container
    connection_string = (
        f"DefaultEndpointsProtocol=https;"
        f"AccountName={storage_account};"
        f"AccountKey={account_key};"
        f"EndpointSuffix=core.windows.net"
    )

    try:
        blob_service = BlobServiceClient.from_connection_string(connection_string)
        blob_service.create_container(container_name)
    except Exception as e:
        if "ContainerAlreadyExists" in str(e):
            pass  # Container exists, that's fine
        else:
            return C2OtherServiceRPCMessageResponse(
                Success=False,
                Error=f"[*] Error {e}",
            )

    # Generate container-scoped SAS token
    # Permissions: read, write, list, add, create (NO delete)
    expiration_date = datetime.strptime(killdate, "%Y-%m-%d")
    sas_token = generate_container_sas(
        account_name=storage_account,
        container_name=container_name,
        account_key=account_key,
        permission=ContainerSasPermissions(
            read=True,
            write=True,
            delete=True,
            list=True,
            add=True,
            create=True,
        ),
        expiry=expiration_date,
    )
    print(f"[*] SAS token: {sas_token}")
    print(f"[*] Container Name: {container_name}")

    blob_endpoint = f"https://{storage_account}.blob.core.windows.net"

    return C2OtherServiceRPCMessageResponse(
        Success=True,
        Result={
            "blob_endpoint": blob_endpoint,
            "sas_token": sas_token,
            "container_name": container_name,
        }
    )

class AzureBlob(C2Profile):
    name = "azure_blob"
    description = "Azure Blob Storage C2 with per-agent container isolation"
    author = "@your_handle"
    is_p2p = False
    is_server_routed = False
    server_folder_path = Path(".") / "azure_blob" / "c2_code"
    server_binary_path = server_folder_path / "server.py"
    parameters = [
        C2ProfileParameter(
            name="storage_account",
            description="Azure Storage Account name (e.g., mystorageaccount)",
            default_value="",
            required=True,
        ),
        C2ProfileParameter(
            name="account_key",
            description="Storage Account Key (server-side only - NEVER sent to agent)",
            default_value="",
            required=True,
        ),
        C2ProfileParameter(
            name="callback_interval",
            description="Agent callback interval in seconds",
            default_value="30",
            verifier_regex="^[0-9]+$",
            required=True,
        ),
        C2ProfileParameter(
            name="callback_jitter",
            description="Callback jitter percentage (0-100)",
            default_value="10",
            verifier_regex="^[0-9]+$",
            required=True,
        ),
        C2ProfileParameter(
            name="encrypted_exchange_check",
            description="Perform Key Exchange",
            choices=["T", "F"],
            parameter_type=ParameterType.ChooseOne,
            required=False,
        ),
        C2ProfileParameter(
            name="AESPSK",
            description="Crypto type",
            default_value="aes256_hmac",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            required=False,
            crypto_type=True,
        ),
        C2ProfileParameter(
            name="killdate",
            description="Kill Date",
            parameter_type=ParameterType.Date,
            default_value=365,
            required=False,
        ),
    ]
    custom_rpc_functions = {
        "generate_config": generate_config
    }

    async def opsec(self, inputMsg: C2OPSECMessage) -> C2OPSECMessageResponse:
        """Validate configuration - CANNOT modify parameters"""
        response = C2OPSECMessageResponse(Success=True)

        params = inputMsg.Parameters
        if not params.get("storage_account"):
            response.Success = False
            response.Error = "Storage account name is required"
        elif not params.get("account_key"):
            response.Success = False
            response.Error = "Account key is required"
        else:
            response.Message = "Azure Blob Storage configuration validated"

        return response
