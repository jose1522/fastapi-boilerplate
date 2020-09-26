from os import environ
import redis

SECRET_KEY = environ.get('SECRET_KEY')
API_KEY = environ.get('API_KEY')
SENDGRID_KEY = environ.get('SENDGRID_KEY')
WTF_CSRF_SECRET_KEY = environ.get('WTF_CSRF_SECRET_KEY')
RECAPTCHA_PUBLIC_KEY = environ.get('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = environ.get('RECAPTCHA_PRIVATE_KEY')

# SQLAlquemy
SQLALQUEMY_DATABASE_URL = environ.get('SQLALQUEMY_DATABASE_URL')

# Flask-Session
SESSION_TYPE = environ.get('SESSION_TYPE')
# SESSION_REDIS = redis.from_url('redis://127.0.0.1:6379')