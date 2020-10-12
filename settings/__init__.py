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
        self.API_USE_SSL = os.environ.get('API_USE_SSL') == 'True'
        self.BROKER_HOST = os.environ.get('BROKER_HOST')
        self.API_RELOAD = os.environ.get('API_RELOAD') == 'True'
        self.API_SUPER_USER = os.environ.get('API_SUPER_USER').split(":")
        self.DB_ENCRYPTION_KEY = os.environ.get('DB_ENCRYPTION_KEY')


settings = Settings()
