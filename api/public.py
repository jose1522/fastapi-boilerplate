from fastapi import APIRouter, Path
from api.validation import *
from database import model
from typing import Optional

public = APIRouter()


@public.get('/{name}')
async def index(greeting: str, name: str = Path(..., title="Your name", min_length=2, max_length=10)):
    return {greeting: name}


@public.post('/authenticate')
async def index(user: UserParams):
    result = await model.User.authenticate(user)
    return result
