from pydantic import BaseModel

class Payload(BaseModel):
    filename: str
    username: str
    filetype: str
    datecreated: str
    filehash: str


