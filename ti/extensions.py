# ti/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_pymongo import PyMongo
import ssl

db = SQLAlchemy()
mongo = PyMongo()
login_manager = LoginManager()