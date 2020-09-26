from flask import Blueprint, session

admin = Blueprint('admin', '__name__')

@admin.route('/')
def index():
    return "Hello World"

@admin.route("/user")
def displayUser():
    return session['user']