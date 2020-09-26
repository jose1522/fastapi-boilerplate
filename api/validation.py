from pydantic import BaseModel
from typing import Optional


class UserParams(BaseModel):
    name: str
    password: str


class TokenParams(BaseModel):
    access_token: str
    token_type: str