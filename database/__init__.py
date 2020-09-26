from mongoengine import connect
from settings import settings

connect(
    db=settings.MONGO_DB,
    authentication_source=settings.MONGO_AUTH_SOURCE,
    username=settings.MONGO_USER,
    password=settings.MONGO_SECRET,
    host=settings.MONGO_HOST
)



