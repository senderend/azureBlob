from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class HostnameArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class HostnameCommand(CommandBase):
    cmd = "hostname"
    needs_admin = False
    help_cmd = "hostname"
    description = "Get system hostname"
    version = 1
    author = "@your_handle"
    argument_class = HostnameArguments
    attackmapping = ["T1082"]

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
