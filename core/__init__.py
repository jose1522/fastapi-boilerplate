from flask import Flask
import datetime
from flask_session import Session
from public.routes import public
from api.routes import api
from admin.routes import admin


app = Flask(__name__)
app.config.from_pyfile('settings.py')
app.permanent_session_lifetime = datetime.timedelta(days=1)

# Register blueprints
app.register_blueprint(public)
app.register_blueprint(api, url_prefix='/api')
app.register_blueprint(admin, url_prefix='/admin')

# Instantiate session
sess = Session()
sess.init_app(app)

# from core import views

