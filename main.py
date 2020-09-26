from core import *
import uvicorn
from settings import settings
import ssl

app = create_app()


def startAPI():
    if settings.API_USE_SSL:
        uvicorn.run(
            "main:app",
            port=settings.API_PORT,
            workers=settings.API_WORKERS,
            reload=settings.API_RELOAD
        )
    else:
        uvicorn.run(
            "main:app",
            port=settings.API_PORT,
            workers=settings.API_WORKERS,
            reload=settings.API_RELOAD,
            ssl_version=ssl.PROTOCOL_SSLv23,
            ssl_keyfile="./core/certs/rootCA-key.pem",
            ssl_certfile="./core/certs/rootCA.pem"
        )


if __name__ == '__main__':
    startAPI()
