#!/usr/bin/env python
from flask import Flask, jsonify
import sys
from flasgger import Swagger
from flasgger.utils import swag_from
from flask_cors import CORS


from endpoints.courses import coursesapi
from endpoints.users import  usersapi


app = Flask(__name__)
Swagger(app, template_file='conf/openapi.yaml')
 # Allow CORS
CORS(app)

# register blueprints. ensure that all paths are versioned!


app.register_blueprint(coursesapi, url_prefix="/")
app.register_blueprint(usersapi, url_prefix="/")

