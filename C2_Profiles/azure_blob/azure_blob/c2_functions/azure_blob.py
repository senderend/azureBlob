from mythic_container.C2ProfileBase import *
from pathlib import Path


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
