from datetime import datetime, timedelta
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from settings import settings
from api.messages import AuthMessage
from api.validation import *
from database import model
import bcrypt


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_hashed_password(password: str):
    password = password.encode('utf8')
    password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf8')
    return password


async def check_password(inputCredentials: UserParams):
    msg = AuthMessage()

    # transform input
    inputCredentials = dict(inputCredentials)

    # get user by username
    inputPassword = inputCredentials.get('password').encode('utf8')
    user = await model.User.searchUser(inputCredentials.get('username'))
    userPassword = user.get('password').encode('utf8')

    # check passwords
    result = bcrypt.checkpw(inputPassword, userPassword)
    msg.authResult(result)

    # add token if the passwords match
    if result:
        token = create_access_token(user)
        msg.addMessage('Token', token)
    return msg


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta is not None:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(weeks=2)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.ENCRYPTION_KEY, algorithm=settings.ENCRYPTION_ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        data = jwt.decode(token, settings.ENCRYPTION_KEY, algorithms=[settings.ENCRYPTION_ALGORITHM])
        username: str = data.get("username")
        user = await model.User.searchUser(username)
        del user['password']
        return user
    except JWTError:
        raise credentials_exception


