from fastapi import APIRouter, Depends, Path
from api.validation import *
from database import model
from core.security.router_dependencies import check_jwt
from typing import Optional

private = APIRouter()


@private.get('/hello')
async def index(name: str = Path(..., title="Your name", min_length=2, max_length=10)):
    return {"hello": name}


################################################################
# User-related endpoints
################################################################

@private.post('/user')
async def new_user(user: UserParams):
    result = await model.User.createUser(user)
    return result


@private.get('/user')
async def get_user(user=Depends(check_jwt)):
    return user


@private.put('/user')
async def update_user(data: UserParams, user=Depends(check_jwt)):
    result = await model.User.updateUser(user, data)
    return result


@private.delete('/user')
async def delete_user(user=Depends(check_jwt)):
    result = await model.User.deleteUser(user)
    return result