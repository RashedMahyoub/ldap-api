from flask import request, make_response
from flask import  Blueprint, jsonify
from .ldapsearchad import LdapsearchAd
from flask.json import jsonify
from bson import json_util
from . import *
import json

usersapi = Blueprint(name="usersapi", import_name=__name__)

# traitement erreur
@usersapi.errorhandler(400)
def create_failed(error):
    return make_response(jsonify({"error": "bad input"}), 400)

@usersapi.errorhandler(500)
def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)

@usersapi.errorhandler(403)
def user_notfound(id):
    message = {
        'status': 403,
        'message': 'User not Found: ' + str(id),
    }
    resp = jsonify(message)
    return resp

@usersapi.errorhandler(404)
def not_found(error=None):
    message = {
        'status': 404,
        'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp


@usersapi.route('/users/get/', methods=['GET'])
def getUsers():

    ldapsearch = LdapsearchAd("192.168.0.204", False, "RESILIENCE", "Administrator", "Admin@123", None)

    ldapsearch.print_info()

    u = {}
    resp = jsonify(json.loads(json_util.dumps(u)))
 
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    app.run(debug=True)
