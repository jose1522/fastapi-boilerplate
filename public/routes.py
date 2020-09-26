from flask import Blueprint, url_for, session, make_response, redirect
from functools import wraps
import json

public = Blueprint('public', '__name__')

def login_required(f):
    # method wraps other functions
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'userName' in session: #if there is a user key in the session object, continue
            return f(*args, **kwargs)
        else:
            return redirect(url_for('index'))
    return wrap

@public.route("/")
def index():
    session['user'] = 'Test'
    res = make_response("Hello World")
    res.set_cookie("genericCookie", json.dumps({"key1":"value1","key2":"value2"}))
    return res

@public.route("/user")
def displayUser():
    return session['user']

@public.route("/logout")
def logout():
    session.clear()
    return "Goodbye World!"