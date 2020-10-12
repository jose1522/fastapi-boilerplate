from fastapi import APIRouter, Path, Depends
from fastapi.security import OAuth2PasswordRequestForm
from core.security.authentication import credentials_exception
from api.validation import *
from database import model
from typing import Optional

public = APIRouter()


@public.post('/token', response_model=TokenParams)
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = UserParams(**form_data.__dict__)
    result = await model.User.authenticate(user)
    if not result.get('Token'):
        raise  credentials_exception
    return {"access_token": result.get("Token"), "token_type": "bearer"}


@public.get('/{name}')
async def index(greeting: str, name: str = Path(..., title="Your name", min_length=2, max_length=10)):
    return {greeting: name}


@public.post('/authenticate')
async def index(user: UserParams):
    result = await model.User.authenticate(user)
    return result
