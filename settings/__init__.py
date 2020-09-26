import os
from dotenv import load_dotenv


class Settings:
    def __init__(self):
        load_dotenv()
        self.ACCESS_TOKEN = os.environ.get('ACCESS_TOKEN')
        self.MONGO_HOST = os.environ.get('MONGO_HOST')
        self.MONGO_DB = os.environ.get('MONGO_DB')
        self.MONGO_USER = os.environ.get('MONGO_USER')
        self.MONGO_AUTH_SOURCE = os.environ.get('MONGO_AUTH_SOURCE')
        self.MONGO_SECRET = os.environ.get('MONGO_SECRET')
        self.ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
        self.ENCRYPTION_ALGORITHM = os.environ.get('ENCRYPTION_ALGORITHM')
        self.API_WORKERS = int(os.environ.get('API_WORKERS'))
        self.API_PORT = int(os.environ.get('API_PORT'))
        self.API_USE_SSL = bool(os.environ.get('API_USE_SSL'))
        self.MONGO_BROKER_DB = os.environ.get('MONGO_BROKER_DB')
        self.API_RELOAD = bool(os.environ.get('API_RELOAD'))


settings = Settings()
