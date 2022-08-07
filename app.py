#!/usr/bin/env python
from flask import Flask, jsonify
import sys
from flask_cors import CORS
from endpoints.users import  usersapi


#test
app = Flask(__name__)

 # Allow CORS
CORS(app,
    resources={r"*": {"origins": "http://localhost:3000",}},
    expose_headers=["Content-Type", "X-CSRFToken"],
    supports_credentials=True,)

# register blueprints. ensure that all paths are versioned!

app.register_blueprint(usersapi, url_prefix="/")

