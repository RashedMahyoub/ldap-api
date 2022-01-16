#!/usr/bin/env python
from flask import Flask, jsonify
import sys
from flasgger import Swagger
from flasgger.utils import swag_from
from flask_cors import CORS
from datetime import timedelta


from flask_jwt_extended import JWTManager

from endpoints.courses import coursesapi
from endpoints.users import  usersapi


#test
app = Flask(__name__)
jwt = JWTManager(app) 

app.config['JWT_SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'  # Change this!
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config["JWT_COOKIE_SECURE"] = False # In production, this should always be set to True

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)
Swagger(app, template_file='conf/openapi.yaml')
 # Allow CORS
CORS(app)

# register blueprints. ensure that all paths are versioned!


app.register_blueprint(coursesapi, url_prefix="/")
app.register_blueprint(usersapi, url_prefix="/")

