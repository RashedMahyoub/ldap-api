from asyncio.windows_events import NULL
from queue import Empty
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

@coursesapi.route('/courses/add/', methods=['POST'])
#@jwt_required()
def addcourse():

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
    course['state'] = "waiting"
    #course['createdAt'] = time.strftime('%d/%m/%y', time.localtime())   
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
# @jwt_required()
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
   # course["UpdatedAt"] = time.strftime('%d/%m/%y', time.localtime())
    try:
        res = courses.update_one({'_id': ObjectId(idcourse)}, {'$set': course})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(courses.find_one({'_id': ObjectId(idcourse)}))))

#**********************************************
# Chapter of a course
#**************************

#Update chapter
@coursesapi.route('/courses/chapters/update/<courseID>/<numberChapter>', methods=['PUT'])
#@jwt_required()
def updateChapterCpurse(courseID, numberChapter):
    
    if ObjectId.is_valid(courseID) == False:
        return id_inalid(courseID)
    course = courses.find_one({'_id': ObjectId(courseID)})
    
    if not request.json:
        abort(400)
        
    if course ==None:
        resp = jsonify({"message": "course does not exist in database"})
        resp.status_code = 404
        return resp 
    data = request.get_json() 
    try:
        res= courses.update_one({'_id': ObjectId(courseID), "chapters.id": str(numberChapter)}, {'$set':{"chapter" : data}})

    except Exception:
        message = {
               'status': 500,
               'message': 'update problem'
            } 
    proj = courses.find_one({'_id': ObjectId(courseID)})
    resp = jsonify(json.loads(json_util.dumps(proj)))
    resp.status_code= 200
    return resp

# Remove chapter
@coursesapi.route('/courses/chapters/remove/<courseID>/<numberChapter>', methods=['PUT'])
#@jwt_required()
def removeChapterCpurse(courseID, numberChapter):
    
    if ObjectId.is_valid(courseID) == False:
        return id_inalid(courseID)
    course = courses.find_one({'_id': ObjectId(courseID)})
    
    if not request.json:
        abort(400)
        
    if course ==None:
        resp = jsonify({"message": "course does not exist in database"})
        resp.status_code = 404
        return resp 
    
    try:
        res = courses.update_one({'_id': ObjectId(courseID)}, {'$pull': {"chapters" : {"id": str(numberChapter)}}})
    except Exception:
        message = {
               'status': 500,
               'message': 'update problem'
            } 
    proj = courses.find_one({'_id': ObjectId(courseID)})
    resp = jsonify(json.loads(json_util.dumps(proj)))
    resp.status_code= 200
    return resp   
    
# Update state course  
@coursesapi.route('/courses/state/<courseID>/<state>', methods=['PUT'])
# @jwt_required()
def coursetUpdateState(courseID, state):

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
@coursesapi.route('/courses/getID/<id>', methods=['GET'])
def coursesByID(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    product = courses.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(product)))
    resp.status_code = 200
    return resp

#Get all instructor courses 
@coursesapi.route('/courses/instructor/<id>', methods=['GET'])
def coursesInstructor(id):
   
    if ObjectId.is_valid(id) == False:
        return id_inalid(id)
    user = users.find_one({'_id': ObjectId(id)})
    if user == None:
        resp = jsonify({"message": "Instructor does not exist in database"})
        resp.status_code = 404
        return resp   
    
    output = []
    for d in courses.find({'instructorID': id}):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

# delete course as a physical delte from collection courses
@coursesapi.route('/courses/delete/<idcourse>', methods=['PUT'])
# @jwt_required()
def deleteOne(idcourse): 
    
    if ObjectId.is_valid(idcourse) == False:
        return not_found()
   
    user = courses.find_one({'_id': ObjectId(idcourse)})
    # course doesn"t exist in dataBase
    if user == None:
        resp = jsonify({"message": "course does not exist in database"})
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
# using GET methdd
@coursesapi.route('/courses/filter/', methods=['GET'])
#@jwt_required()
def coursesFilter():

    priceget = request.args.get('price')
    search = request.args.get('search')
    categories = request.args.getlist('categories')
    page = request.args.get("page")
    orders = request.args.get('order')
    limitcollection = request.args.get('limit')
    startIndex = (int(page) - 1) * int(limitcollection)

        
    order = ['createdAt', -1]
    # order By 
      #highest: order from hights prices to lowest. 
    if orders == 'highest':
       order = ['price', -1]
    if orders == 'lowest':
        order = ['price', 1]
    if orders == "recent":
       order = ['createdAt', -1]

    #search instructor    
    idInscturor = []

    titleFilter = [];

    if search:
        for d in users.find({'name': {'$regex' : search, '$options' : 'i' }, "Instructor": {"$exists": True}}, {'_id': 1}):
            idInscturor.append(str(d['_id']))         
    
    #search course title    
    #Must be an or 
    title = {'title': {'$regex' : search, '$options' : 'i' }} if search else None  
      
    # Price filter
    price = None;
    if priceget == "free":
        price =  {'price': {'$eq': 0}}
    if priceget =="paid":
        price =  {'price': {'$gt': 0}}
    if priceget =="all":
        price =  None;

    filter =[{'state': 'available'}]

    if title:
        titleFilter.append(title);

    if len(idInscturor) > 0:
        inst = {'instructorID' :{"$in": idInscturor}}
        titleFilter.append(inst)

    if price:
        filter.append(price);

    if len(categories) > 0 :
        category = {'category': {"$in": categories}}
        filter.append(category)
            
    fullfilter = {};
    if titleFilter:
        fullfilter = { '$and': filter, '$or': titleFilter }
    else:
        fullfilter = { '$and': filter }

    # filter courses get document counts
    output = []
    results = courses.find(fullfilter).sort(order[0], order[1]).limit(int(limitcollection)).skip(startIndex);
    results_count = courses.count_documents(fullfilter)
    for d in results: 
        output.append(json.loads(json_util.dumps(d)))
   
    resp = jsonify({ 'courses': output, 'count': results_count})
    #resp = jsonify(json.loads(json_util.dumps(filter)))
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

#**********************************************
# Reports
#**************************
 
 ## Add report to a given course Object(iduser, raison)
@coursesapi.route('/courses/reports/add/<idcourse>', methods=['POST'])
def addreportCourse(idcourse):
      
    data = request.get_json()
    if ObjectId.is_valid(idcourse) == False:
        return not_found()
    
    if not request.json:
        abort(400)
    if 'raison' not in request.json:
        abort(400)
   
    user = users.find_one({'_id': ObjectId(str(data['iduser']))})
    
    course = courses.find_one({'_id': ObjectId(idcourse)}) 
    # user of provier not exist in dataBase
    if user == None or course== None:
        resp = jsonify({"message": "user Or course not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection courses
    data['date'] = time.strftime('%d/%m/%y', time.localtime())
    try:
        courses.update_one({'_id': ObjectId(idcourse)}, {'$push': {"reports": data}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp
    return success()

## Add report to comment
@coursesapi.route('/courses/reports/addComment/<idcomment>', methods=['POST'])
def addreportToComment(idcomment):
      
    data = request.get_json()
    if ObjectId.is_valid(idcomment) == False:
        return not_found()
    
    if not request.json:
        abort(400)
    if 'reason' not in request.json:
        abort(400)
   
    user = users.find_one({'_id': ObjectId(str(data['iduser']))})
    
    comment = comments.find_one({'_id': ObjectId(idcomment)}) 
    # user of provier not exist in dataBase
    if user == None or comment== None:
        resp = jsonify({"message": "user Or comment does not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection comments
    #data['date'] = time.strftime('%d/%m/%y', time.localtime())
    try:
        comments.update_one({'_id': ObjectId(idcomment)}, {'$push': {"reports": data}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp
    return success()

## Add report to reply of a given comment
@coursesapi.route('/courses/reports/replies/addReply/<idcomment>/<idReply>', methods=['PUT'])
def addreportToReply(idcomment, idReply):
      
    if ObjectId.is_valid(idcomment) == False:
        return not_found()
    
    if not request.json:
        abort(400)
    
    data = request.get_json()
    if 'reason' not in request.json:
        abort(400)
    
    user = users.find_one({'_id': ObjectId(str(data['iduser']))})
    comment = comments.find_one({'_id': ObjectId(idcomment)}) 
   
    # user of provier not exist in dataBase
    if comment == None or user == None:
        resp = jsonify({"message": "comment or user does not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection comments
   
    try:
        comments.update_one({'_id': ObjectId(idcomment), 'replies.IdReply': ObjectId(idReply) }, {'$push': {"replies.$.reports": data}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp
    return success()

#get All reports of a given course
@coursesapi.route('/courses/reports/courses/<id>', methods=['GET'])
def allReportsOfcourse(id):
    
    if ObjectId.is_valid(id) == False:
        abort(400)
    output = []
    for d in courses.find({'_id': ObjectId(id)}, {'reports': 1}):
        if 'reports' in d:
            output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#get All reports of a comments and replies from a course
@coursesapi.route('/comments/reports/repliescomments/<idcourse>', methods=['GET'])
def allReportsOfCommentReplies(idcourse):
    
    output = []
    for d in comments.find({'course': str(idcourse)}).sort([('createdAt', -1)]):
        if 'reports' in d:
            for r in d['reports']:
                r['type'] = 'comment'
                r['commentId'] = d['_id']
                output.append(json.loads(json_util.dumps(r)))
        if 'replies' in d:
            for m in d['replies']:
                if 'reports' in m:
                    for r in m['reports']:
                        r['type'] = 'reply'
                        r['commentId'] = d['_id']
                        r['replyId'] = m['IdReply']
                        output.append(json.loads(json_util.dumps(r)))


    resp = jsonify(output)
    resp.status_code = 200
    return resp

#get All reports of a given comment
@coursesapi.route('/comments/reports/comments/<idcomment>', methods=['GET'])
def allReportsOfComment(idcomment):
    
    output = []
    for d in comments.find({'_id': ObjectId(idcomment)}, {'reports': 1}):
        if 'reports' in d:
            output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#**********************************************
# Comments
#**************************
 
## add comment as mongodb Object
@coursesapi.route('/courses/comments/add/<idcourse>', methods=['POST'])
def addcommentCourse(idcourse):
      
    data = request.get_json()
    if ObjectId.is_valid(idcourse) == False:
        return not_found()
    
    if not request.json:
        abort(400)
    if 'comment' not in request.json :
        abort(400)
    if 'user' not in request.json :
        abort(400)
   
    user = users.find_one({'_id': ObjectId(str(data['user']))})
    
    course = courses.find_one({'_id': ObjectId(idcourse)}) 
    # user of provier not exist in dataBase
    if user == None or course== None:
        resp = jsonify({"message": "user Or course not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection customers
    data['course'] = idcourse
    try:
        comments.insert_one(data)
    except Exception:
        message = {
            'status': 500,
            'message': 'insert problem'
        }
        resp = jsonify(message)
        return resp

    return success()

#get All comments of a given course
@coursesapi.route('/courses/comments/<id>', methods=['GET'])
def allCommentsOfcourse(id):
    
    if ObjectId.is_valid(id) == False:
        abort(400)
    output = []
    for d in comments.find({'course': str(id)}).sort([('createdAt', -1)]):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

#get comment by Id
@coursesapi.route('/courses/comments/get/<id>', methods=['GET'])
def commentByID(id):
    
    if ObjectId.is_valid(id) == False:
        abort(400)
    
    u = comments.find_one({'_id': ObjectId(id)})
    resp = jsonify(json.loads(json_util.dumps(u)))
    resp.status_code = 200
    return resp

#get reply by Id
@coursesapi.route('/courses/replies/get/<id>', methods=['GET'])
def replyById(id):
    
    if ObjectId.is_valid(id) == False:
        abort(400)
    
    c = comments.find({"replies":{"$elemMatch": {"IdReply": ObjectId(id)}}},  {"_id": 0, "replies": {"$elemMatch": {"IdReply": ObjectId(id)}}})
    resp = jsonify(json.loads(json_util.dumps(c)))
    resp.status_code = 200
    return resp

# remove a comment by ID
@coursesapi.route('/courses/comments/delete/<idcomment>/', methods=['PUT'])
#@jwt_required()
def userRemoveComment(idcomment):

    if ObjectId.is_valid(idcomment) == False:
        return id_inalid(idcomment)

    com = comments.find_one({'_id': ObjectId(idcomment)})
    # user of provier not exist in dataBase
    if com == None:
        resp = jsonify({"message": "comment not exist"})
        resp.status_code = 404
        return resp
    
    # Exist: remove the comments  
    # Physical delete from collection courses 
    try:
        comments.delete_one({'_id': ObjectId(idcomment)})
    except Exception:
        abort(500)
    return success()

# Add reply to comment
@coursesapi.route('/courses/comments/addReply/<idcomment>', methods=['POST'])
def addReplyTocomment(idcomment):
      
    data = request.get_json()
    if ObjectId.is_valid(idcomment) == False:
        return not_found()
    
    if not request.json:
        abort(400)
      
    com = comments.find_one({'_id': ObjectId(idcomment)})
    
    # comment does not exist in dataBase
    if com == None :
        resp = jsonify({"message": "comment does not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection course
    data['IdReply'] = ObjectId()
    try:
        comments.update_one({'_id': ObjectId(idcomment)}, {'$push': {"replies": data}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp

    return success()

# Remove a reply for a given comment
@coursesapi.route('/courses/comments/deleteReply/<idcomment>/<idReply>', methods=['PUT'])
def deleteReplyForcomment(idcomment,idReply):
      
    data = request.get_json()
    if ObjectId.is_valid(idcomment) == False:
        return not_found()
    
    if not request.json:
        abort(400)
      
    com = comments.find_one({'_id': ObjectId(idcomment)})
    
    # comment does not exist in dataBase
    if com == None :
        resp = jsonify({"message": "comment does not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection course
    try:
        comments.update_one({'_id': ObjectId(idcomment)}, {'$pull': {"replies": {"IdReply": ObjectId(idReply)}}})
    except Exception:
        message = {
            'status': 500,
            'message': 'delete problem'
        }
        resp = jsonify(message)
        return resp

    return success()

#**********************************************
# Rating
#**************************
# Update course rating
@coursesapi.route('/courses/update/rating/<courseid>', methods=['PUT'])
# @jwt_required()
def coursetUpdateRate(courseid):

    data = request.get_json()

    if not request.json:
        abort(400)

    course = courses.find_one({'_id': ObjectId(courseid)}) 
    if course == None:
      return not_found()
    try:
        course = courses.update_one({'_id': ObjectId(courseid)}, {'$set': {'rating': data }})
    except Exception:
        message = {
               'status': 500,
               'message': 'update problem'
             }
        resp = jsonify(message)
        return resp
    
    return success()

#**********************************************
# Notifications
#**************************
 
## add Notification to a given course 
@coursesapi.route('/courses/notifications/add/<idcourse>', methods=['POST'])
def addNotificationCourse(idcourse):
      
    data = request.get_json()
    if ObjectId.is_valid(idcourse) == False:
        return not_found()
    
    if not request.json:
        abort(400)
  
    course = courses.find_one({'_id': ObjectId(idcourse)}) 
    # user of provier not exist in dataBase
    if course== None:
        resp = jsonify({"message": " course does not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection course    
   
    data['IdNotification'] = ObjectId()
    try:
        courses.update_one({'_id': ObjectId(idcourse)}, {'$push': {"notifications": data}})
    except Exception:
        message = {
            'status': 500,
            'message': 'insert problem'
        }
        resp = jsonify(message)
        return resp


    return success()

#get All Notification of a given course
@coursesapi.route('/courses/notifications/<id>', methods=['GET'])
def allNotificationsOfcourse(id):
    
    if ObjectId.is_valid(id) == False:
        abort(400)
        
    output = []
    for d in courses.find({'_id': ObjectId(id)}, {'notifications': 1}):
        if 'notifications' in d:
            output = json.loads(json_util.dumps(d["notifications"]))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

# remove a notification of a given courses
@coursesapi.route('/courses/notifications/delete/<idcourse>/<idNotification>', methods=['PUT'])
#@jwt_required()
def userRemoveNotificationOfCourses(idcourse, idNotification):

    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    crs = courses.find_one({'_id': ObjectId(idcourse)})
    # user of provier not exist in dataBase
    if crs == None:
        resp = jsonify({"message": "course not exist"})
        resp.status_code = 404
        return resp
    
    # Exist: update collection course
    try:
        courses.update_one({'_id': ObjectId(idcourse)}, {'$pull': {"notifications": {"IdNotification": ObjectId(idNotification)}}})
    except Exception:
        message = {
            'status': 500,
            'message': 'delete problem'
        }
        resp = jsonify(message)
        return resp
    return success()

# delete all notifications of a given courses
@coursesapi.route('/courses/notifications/delete/<idcourse>/', methods=['PUT'])
#@jwt_required()
def deleteAllNotificationOfCourses(idcourse):

    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    crs = courses.find_one({'_id': ObjectId(idcourse)})
    # user of provier not exist in dataBase
    if crs == None:
        resp = jsonify({"message": "course not exist"})
        resp.status_code = 404
        return resp
    
    # Exist: update collection course
    try:
        courses.update_one({'_id': ObjectId(idcourse)}, {'$set': {"notifications": []}})
    except Exception:
        message = {
            'status': 500,
            'message': 'delete problem'
        }
        resp = jsonify(message)
        return resp
    return success()


#**********************************************
# Recents & Course Progress
#**************************
# add course to recents
@coursesapi.route('/courses/recents/add/<iduser>/<idcourse>', methods=['PUT'])
#@jwt_required()
def addCourseToRecents(iduser, idcourse):

    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)

    crs = courses.find_one({'_id': ObjectId(idcourse)})
    user = users.find_one({'_id': ObjectId(iduser)})

    # user of provier not exist in dataBase
    if crs == None:
        resp = jsonify({"message": "course not exist"})
        resp.status_code = 404
        return resp

    if user == None:
        return user_notfound(iduser)

    # Exist: update collection course
    try:
        users.update_one({'_id': ObjectId(iduser)}, {'$addToSet': {"recents": idcourse}})
    except Exception:
        message = {
            'status': 500,
            'message': 'add problem'
        }
        resp = jsonify(message)
        return resp

    updatedUser = users.find_one({'_id': ObjectId(iduser)})
    resp = jsonify(json.loads(json_util.dumps(updatedUser)))
    resp.status_code= 200
    return resp


# add course to recents
@coursesapi.route('/courses/recents/remove/<iduser>/<idcourse>', methods=['PUT'])
#@jwt_required()
def removeCourseFromRecents(iduser, idcourse):

    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)

    crs = courses.find_one({'_id': ObjectId(idcourse)})
    user = users.find_one({'_id': ObjectId(iduser)})

    # user of provier not exist in dataBase
    if crs == None:
        resp = jsonify({"message": "course not exist"})
        resp.status_code = 404
        return resp

    if user == None:
        return user_notfound(iduser)

    # Exist: update collection course
    try:
        users.update_one({'_id': ObjectId(iduser)}, {'$pull': {"recents": idcourse}})
    except Exception:
        message = {
            'status': 500,
            'message': 'delete problem'
        }
        resp = jsonify(message)
        return resp

    updatedUser = users.find_one({'_id': ObjectId(iduser)})
    resp = jsonify(json.loads(json_util.dumps(updatedUser)))
    resp.status_code= 200
    return resp


# add course to recents
@coursesapi.route('/courses/progress/<iduser>/<idcourse>', methods=['PUT'])
#@jwt_required()
def updateCourseProgress(iduser, idcourse):

    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)

    crs = courses.find_one({'_id': ObjectId(idcourse)})
    user = users.find_one({'_id': ObjectId(iduser)})

    # user of provier not exist in dataBase
    if crs == None:
        resp = jsonify({"message": "course not exist"})
        resp.status_code = 404
        return resp

    if user == None:
        return user_notfound(iduser)

    # Exist: update collection course
    try:
        users.update_one({'_id': ObjectId(iduser)}, {'$set': {"recents": idcourse}})
    except Exception:
        message = {
            'status': 500,
            'message': 'delete problem'
        }
        resp = jsonify(message)
        return resp
    return success()

if __name__ == '__main__':
    app.run(debug=True)
