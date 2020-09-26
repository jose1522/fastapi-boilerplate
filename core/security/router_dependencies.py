from fastapi import Header, HTTPException, Depends
from settings import settings
from core.security.authentication import get_current_user, oauth2_scheme


async def check_token(x_token: str = Header(...)):
    if x_token != settings.ACCESS_TOKEN:
        raise HTTPException(status_code=400, detail='X-Token header invalid')


async def check_jwt(token: str = Depends(oauth2_scheme)):
    data = await get_current_user(token)
    return data
