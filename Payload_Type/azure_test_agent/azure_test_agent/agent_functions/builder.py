from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
import os
import json
import base64
from datetime import datetime, timedelta
from pathlib import Path

from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions


class AzureTestAgent(PayloadType):
    name = "azure_test_agent"
    author = "@your_handle"
    description = "Minimal Python agent for testing Azure Blob C2 profile"
    supported_os = [SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows]
    file_extension = "py"
    wrapper = False
    wrapped_payloads = []
    supports_dynamic_loading = False
    mythic_encrypts = True
    translation_container = None
    agent_type = "agent"
    agent_path = Path(".") / "azure_test_agent" / "agent_code"
    agent_code_path = Path(".") / "azure_test_agent" / "agent_code"
    agent_icon_path = None

    c2_profiles = ["azure_blob"]

    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["py", "exe"],
            default_value="py",
            description="Output as Python script or compiled executable",
        ),
    ]

    build_steps = [
        BuildStep(step_name="Provisioning Azure Container", step_description="Creating container and generating SAS token"),
        BuildStep(step_name="Stamping Configuration", step_description="Embedding configuration into agent"),
        BuildStep(step_name="Finalizing Payload", step_description="Building final payload"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)

        try:
            # Read agent template
            agent_template_path = self.agent_code_path / "agent.py"
            if not agent_template_path.exists():
                resp.status = BuildStatus.Error
                resp.build_stderr = f"Agent template not found: {agent_template_path}"
                return resp

            with open(agent_template_path, "r") as f:
                agent_code = f.read()
            killdate = None
            # Process C2 profiles
            for c2 in self.c2info:
                profile_name = c2.get_c2profile()["name"]

                if profile_name == "azure_blob":
                    params = c2.get_parameters_dict()
                    killdate = params.get("killdate", None)
                    storage_account = params.get("storage_account", "")
                    account_key_param = params.get("account_key", "")
                    # crypto_type params return dict with enc_key/dec_key
                    if isinstance(account_key_param, dict):
                        account_key = account_key_param.get("enc_key", "") or account_key_param.get("value", "")
                    else:
                        account_key = str(account_key_param) if account_key_param else ""

                    callback_interval = str(params.get("callback_interval", "30"))
                    callback_jitter = str(params.get("callback_jitter", "10"))

                    aes_key_param = params.get("AESPSK", "")
                    if isinstance(aes_key_param, dict):
                        aes_key = aes_key_param.get("enc_key", "")
                    else:
                        aes_key = str(aes_key_param) if aes_key_param else ""

                    if not storage_account or not account_key:
                        resp.status = BuildStatus.Error
                        resp.build_stderr = "Missing storage_account or account_key"
                        return resp

                    config_data = await SendMythicRPCOtherServiceRPC(MythicRPCOtherServiceRPCMessage(
                        ServiceName="azure_blob",
                        ServiceRPCFunction="generate_config",
                        ServiceRPCFunctionArguments={
                            "killdate": killdate,
                            "storage_account": storage_account,
                            "account_key": account_key,
                            "payload_uuid": self.uuid
                        }
                    ))
                    if not config_data.Success:
                        resp.status = BuildStatus.Error
                        resp.build_stderr = f"Build failed: {config_data.Error}"
                        return resp
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Provisioning Azure Container",
                            StepStdout=f"Container provisioned with scoped SAS token\nEndpoint: {config_data.Result['blob_endpoint']}",
                            StepSuccess=True
                        )
                    )

                    # Step 2: Stamp configuration into agent
                    await SendMythicRPCPayloadUpdatebuildStep(
                        MythicRPCPayloadUpdateBuildStepMessage(
                            PayloadUUID=self.uuid,
                            StepName="Stamping Configuration",
                            StepStdout="Embedding Azure configuration into agent",
                            StepSuccess=True
                        )
                    )

                    # Replace placeholders (account_key NEVER goes to agent)
                    agent_code = agent_code.replace("BLOB_ENDPOINT_PLACEHOLDER", config_data.Result['blob_endpoint'])
                    agent_code = agent_code.replace("CONTAINER_NAME_PLACEHOLDER", config_data.Result['container_name'])
                    agent_code = agent_code.replace("CONTAINER_SAS_PLACEHOLDER", config_data.Result['sas_token'])
                    agent_code = agent_code.replace("CALLBACK_INTERVAL_PLACEHOLDER", callback_interval)
                    agent_code = agent_code.replace("CALLBACK_JITTER_PLACEHOLDER", callback_jitter)
                    agent_code = agent_code.replace("AGENT_UUID_PLACEHOLDER", self.uuid)

                    if aes_key and aes_key != "none":
                        agent_code = agent_code.replace("AES_KEY_PLACEHOLDER", aes_key)
                    else:
                        agent_code = agent_code.replace("AES_KEY_PLACEHOLDER", "")

            # Step 3: Finalize payload
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Finalizing Payload",
                    StepStdout="Payload ready",
                    StepSuccess=True
                )
            )

            resp.payload = agent_code.encode()
            resp.status = BuildStatus.Success
            resp.build_message = "Azure Blob agent built successfully"

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_stderr = f"Build failed: {str(e)}"

        return resp
