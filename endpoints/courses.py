
from flask import request, make_response, abort
from flask import Flask, Blueprint, jsonify
from flask_pymongo import PyMongo
import os
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util
import time
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from endpoints.utilsFunction import *
from . import *

coursesapi = Blueprint(name="coursesapi", import_name=__name__)

#traitement erreur 
@coursesapi.errorhandler(400)
def create_failed(error):
  return make_response(jsonify({"error": "bad input"}), 400)
  
@coursesapi.errorhandler(500)
def internalServer(error):
  return make_response(jsonify({'error': 'Internal Server Error' }), 500)

@coursesapi.errorhandler(403)
def user_notfound(id):
    message = {
               'status': 403,
               'message': 'User not Found: ' + id,
             }
    resp = jsonify(message)
    return resp


@coursesapi.errorhandler(404)
def not_found(error=None):
    message = {
               'status': 404,
               'message': 'Not Found: ' + request.url,
             }
    resp = jsonify(message)
    resp.status_code = 404
    return resp

@coursesapi.route('/courses/add/<instructorID>', methods=['POST'])
@jwt_required()
def addcourse(instructorID):

    if not request.json:
        abort(400)
       
    if  'instructorID' not in request.json or 'title' not in request.json or 'category' not in request.json or 'price' not in request.json or 'description' not in request.json: 
        abort(400)
    if 'instructorID' in request.json and ObjectId.is_valid(request.json['instructorID']) == False:
        return id_inalid(request.json['instructorID'])
    
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
    if 'description' in request.json and isinstance(request.json['description'], str) == False:
        abort(400)
    
    course = request.get_json()
    courses['state'] = "waiting"
    course['createdAt'] = time.strftime('%d/%m/%y', time.localtime())   
    try:
        c = courses.insert_one(course)
    except Exception:
        abort(500)
    proj = courses.find_one({'_id': ObjectId(c.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(proj)))
    resp.status_code= 200
    return resp
    
#get All courses 
@coursesapi.route('/courses/getAll/', methods=['GET'])
def allcourses():
    
    output = []
    for d in courses.find().sort('createdAt', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#Search courses by category 
@coursesapi.route('/courses/get/<category>', methods=['GET'])
def coursesByCategory(category):
    
    output = []
    for d in courses.find({'category': str(category), 'state': "available"}):
       output.append(json.loads(json_util.dumps(d)))
   
    resp = jsonify(output)
    resp.status_code=200
    return resp  

#Update course
@coursesapi.route('/courses/update/<idcourse>', methods=['POST'])
@jwt_required()
def  updatecourse(idcourse):
    
    if not request.json:
        abort(400)

    if ObjectId.is_valid(idcourse) == False:
        abort(400)
    if  'instructorID' not in request.json or 'title' not in request.json or 'category' not in request.json or 'price' not in request.json or 'description' not in request.json: 
        abort(400)
    if 'instructorID' in request.json and ObjectId.is_valid(request.json['instructorID']) == False:
        return id_inalid(request.json['instructorID'])
    
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
    if 'description' in request.json and isinstance(request.json['description'], str) == False:
        abort(400)

    course = request.get_json()
    course["UpdatedAt"] = time.strftime('%d/%m/%y', time.localtime())
    try:
        res = users.update_one({'_id': ObjectId(idcourse)}, {'$set': course})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(users.find_one({'_id': ObjectId(idcourse)}))))


# Update state course  
@coursesapi.route('/courses/state/<courseID>/<state>', methods=['PUT'])
def projectUpdateState(courseID, state):

    course = courses.find_one({'_id': ObjectId(courseID)}) 
    if course == None:
      return not_found()
    try:
        course = courses.update_one({'_id': ObjectId(courseID)}, {'$set': {'state': state, 'UpdatedAt': time.strftime('%d/%m/%y', time.localtime())}})
    except Exception:
        message = {
               'status': 500,
               'message': 'update problem'
             }
        resp = jsonify(message)
        return resp
    
    return success()

#Search course by Id 
@coursesapi.route('/courses/get/<id>', methods=['GET'])
def coursesByID(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    product = courses.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(product)))
    resp.status_code = 200
    return resp

# delete course as a physical delte from collection courses
@coursesapi.route('/courses/delete/<idcourse>', methods=['PUT'])
def deleteOne(idcourse): 
    
    if ObjectId.is_valid(idcourse) == False:
        return not_found()
   
    user = courses.find_one({'_id': ObjectId(idcourse)})
    # course doesn"t exist in dataBase
    if user == None:
        resp = jsonify({"message": "course not exist in database"})
        resp.status_code = 404
        return resp
    # Physical delete from collection courses 
    try:
        courses.delete_one({'_id': ObjectId(idcourse)})
    except Exception:
        abort(500)
    #search ID students subscibed on this course
    students = courses.find_one({'_id': ObjectId(idcourse)}) 
    
    # Exist: remove the id course from list courses of student    
    for s in students['students']:
        try:
          users.update_one({'_id': ObjectId(s)}, {'$pull': {"courses": {"id" : ObjectId(idcourse)}}})
        except Exception:
            abort(500)
    return success()

#get All courses with filter: categories, price,  instructor name and Course title 
# using post methdd
@coursesapi.route('/courses/filter/', methods=['POST'])
def coursesFilter():

    if not request.json:
        abort(400)

    data = request.json
    filter = {}
    orderby ={}
    # serach all instructors ID match the name of instructor
    if 'instructor' in data:
        idInscturor = []
        for d in users.find({'name': {'$regex' : data['instructor'], '$options' : 'i' }}, {"Isinstructor": True}):
            idInscturor.append(d)         
        filter['instructor'] = {"$in": idInscturor}
    
    if 'coursesname' in data:
        filter['title']  = {'$regex' : data['coursesname'], '$options' : 'i' }
    if 'categories' in data:
       filter['category'] = {"$in": data['categories']}
    
    filter['state'] = "available"
        
    output = []
    for d in courses.find({ "$query": filter}): 
        output.append(json.loads(json_util.dumps(d)))
    
    resp = jsonify(output)
    resp.status_code = 200
    return resp

#**********************************************
# Categories
#**************************
#get All categories 
@coursesapi.route('/courses/categories/', methods=['GET'])
def allCategories():
    
    output = []
    for d in categories.find():
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp


@coursesapi.route('/categories/add', methods=['POST'])
def addcategories():

    if not request.json:
        abort(400)
       
    
    if 'title' in request.json and isinstance(request.json['title'], str) == False:
        abort(400)
    if 'description' in request.json and isinstance(request.json['description'], str) == False:
        abort(400)
    
    cat = request.get_json()
   
    try:
        c = categories.insert_one(cat)
    except Exception:
        abort(500)
    c = categories.find_one({'_id': ObjectId(c.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(c)))
    resp.status_code= 200
    return resp

if __name__ == '__main__':
    app.run(debug=True)

