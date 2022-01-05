from bson.objectid import ObjectId

from flask_pymongo import PyMongo
from flask import Flask, Blueprint, jsonify
from flask_jwt_extended import JWTManager
from datetime import timedelta


from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import get_jwt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies

from datetime import datetime
from datetime import timedelta
from datetime import timezone

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'elearningDB'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/elearningDB'
#app.config['MONGO_URI'] = 'mongodb://masterfix:w5anJSwc1NhLJAnS@cluster0-shard-00-00.iwl07.mongodb.net:27017,cluster0-shard-00-01.iwl07.mongodb.net:27017,cluster0-shard-00-02.iwl07.mongodb.net:27017/masterfixDB?ssl=true&replicaSet=atlas-jej3az-shard-0&authSource=admin&retryWrites=true&w=majority'


app.config['JWT_SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'  # Change this!
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config["JWT_COOKIE_SECURE"] = False # In production, this should always be set to True

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)

jwt = JWTManager(app) 

mongo = PyMongo(app)
users = mongo.db.users
courses = mongo.db.courses
categories = mongo.db.categories



