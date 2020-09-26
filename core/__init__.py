from fastapi import FastAPI, Depends
from api.private import private
from api.public import public
from core.security.router_dependencies import *


def create_app():
    app = FastAPI()
    app.include_router(private,
                       tags=['Private'],
                       prefix='/secure',
                       dependencies=[Depends(check_jwt)],
                       responses={404: {"description": "Not found"}})
    app.include_router(public,
                       tags=['Public'],
                       responses={404: {"description": "Not found"}})
    return app
