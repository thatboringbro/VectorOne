from pydantic import BaseModel

class Payload(BaseModel):
    filename: str
    username: str
    filetype: str
    datecreated: str
    filehash: str
    filepath: str = ""
    device_name: str = ""
    device_id: str = ""


class EndpointHeartbeat(BaseModel):
    device_id: str
    device_name: str
    username: str
    os_version: str
    domain_name: str = ""


class AgentHeartbeat(BaseModel):
    agent_id: str
    hostname: str
    ip_address: str
    os_version: str


class CommandRequest(BaseModel):
    filepath: str
    action: str
    
class AnalystLogin(BaseModel):
    email: str
    password: str

