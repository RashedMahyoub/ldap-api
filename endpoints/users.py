from math import trunc
from flask import request, make_response, abort, session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message

from flask import Flask, Blueprint, jsonify, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pymongo import PyMongo
import uuid
from werkzeug.utils import secure_filename
import json
from flask.json import jsonify
from bson.objectid import ObjectId
from bson import objectid, json_util
import time
from datetime import timedelta
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from . import *
from endpoints.utilsFunction import *
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies
from flask_mail import Mail, Message

usersapi = Blueprint(name="usersapi", import_name=__name__)

#email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'you email'
app.config['MAIL_PASSWORD'] = 'you password'
app.config['SECRET_KEY'] ='01428!4f2af45d3a4e161a7dd2d17fdae47f'
app.config['SECURITY_PASSWORD_SALT'] ='01428!4f2a4e161a7dd2d17fg45!e47f'
mail = Mail(app)
mail.init_app(app)

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


@usersapi.route('/users/register/', methods=['POST'])
def createUser():

    if not request.json:
        abort(400)
    if 'name' not in request.json or 'password' not in request.json or 'email' not in request.json:
        abort(400) 
    if isinstance(request.json['name'], str) == False:
        abort(400)
    if isinstance(request.json['password'], str) == False:
        abort(400)
    if 'city' in request.json and isinstance(request.json['city'], str) == False:
        abort(400)
    if 'counrty' in request.json and isinstance(request.json['counrty'], str) == False:
        abort(400)
    if isinstance(request.json['email'], str) == False:
        abort(400)
    
    datauser = request.get_json()
    
    user = users.find_one({'email': datauser['email']})

    if user:
        resp = jsonify({"message": "An account already registered by this Email"})
        resp.status_code = 403
        return resp

    datauser['created'] = time.strftime('%d/%m/%y', time.localtime())
    datauser['password'] = generate_password_hash(datauser['password'])
    datauser['IsConfirmed'] = False
    
    try:
        res = users.insert_one(datauser)
    except Exception:
        return internalServer()
    
    # Send confirmation Email    
    
    token = generate_confirmation_token(datauser['email'])
    
    url = url_for('usersapi.confirm_email', token=token, _external=True)
    text = 'Your link is {}'.format(url)
    subject = "Please confirm your email"
    send_email(datauser['email'], subject, text)

    u = users.find_one({'_id': ObjectId(res.inserted_id)})
    resp = jsonify(json.loads(json_util.dumps(u)))
 
    resp.status_code = 200
    return resp

# Confiramtion Email
@usersapi.route('/confirm_email/<token>')
def confirm_email(token):
    
    try:
        email = confirm_token(token)
    except:
        return '<h1>The token is expired!</h1>'
   
    try:
        res = users.update_one({'email': email}, {'$set': {'IsConfirmed': True}})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(users.find_one({'email': email}))))

# Upgrade user to Instructor
@usersapi.route('/users/beInstructor/<userId>', methods=['PUT'])
@jwt_required()
def upgradeUser(userId):

    if not request.json:
        abort(400)
    if ObjectId.is_valid(userId) == False:
        return id_inalid(userId)
    
    instructor = request.get_json()
    # waiting for improved by admin
    instructor['instructorAt'] = time.strftime('%d/%m/%y', time.localtime())
    
    try:
        res = users.update_one({'_id': ObjectId(userId)}, {
                               '$set': {'Instructor': instructor}})
    except Exception:
        abort(500)
    if res.modified_count == 0:
        return user_notfound(userId)

    return jsonify(json.loads(json_util.dumps(users.find_one({'_id': ObjectId(userId)}))))

# update  user information
@usersapi.route('/users/<Id>', methods=['PUT'])
#@jwt_required(refresh=True)
def updateUser(Id):

    if not request.json:
        abort(400)
    if ObjectId.is_valid(Id) == False:
        return id_inalid(Id)   
   
    user = users.find_one({'_id': ObjectId(Id)})
    
    # user not exist in dataBase
    if user == None:
        resp = jsonify({"message": "The user not exist in database"})
        resp.status_code = 404
        return resp
  
    if 'name' in request.json and isinstance(request.json['name'], str) == False:
        abort(400)
    if 'city' in request.json and isinstance(request.json['city'], str) == False:
        abort(400)
    if 'counrty' in request.json and isinstance(request.json['counrty'], str) == False:
        abort(400)
    if isinstance(request.json['email'], str) == False:
        abort(400)
    
    user = request.get_json()
       
    try:
        res = users.update_one({'_id': ObjectId(Id)}, {'$set': user})
    except Exception:
        abort(500)
    
    return jsonify(json.loads(json_util.dumps(users.find_one({'_id': ObjectId(Id)}))))

# update user email/password
@usersapi.route('/users/emailPassword/<Id>', methods=['PUT'])
@jwt_required(refresh=True)
def updateEmailPasswordUser(Id):

    if not request.json:
        abort(400)
    
    if ObjectId.is_valid(Id) == False:
        return id_inalid(Id)
    data = request.get_json()
    if "newPassword" not in data and "newEmail" not in data:
        abort(400)
    #check password
    user = users.find_one({'_id': ObjectId(Id)})
    response= jsonify({})
    # user not exist in dataBase
    if user == None:
        resp = jsonify({"message": "The user not exist in database"})
        resp.status_code = 404
        return resp
     
    if check_password_hash(user['password'], data['password']):
        
        if 'newEmail' in data:      
            try:
                res = users.update_one({'_id': ObjectId(Id)}, {'$set': {'email': data['newEmail']}})
            except Exception:
                abort(500)
            # Send confirmation Email    
    
            token = generate_confirmation_token(data['newEmail'])    
            url = url_for('usersapi.confirm_email', token=token, _external=True)
            text = 'Your link is {}'.format(url)
            subject = "Please confirm your email"
            send_email(data['newEmail'], subject, text)   
            try:
              res = users.update_one({'_id': ObjectId(Id)}, {'$set': {'IsConfirmed': False}})
            except Exception:
                abort(500)    
        else:            
            Newpassword = generate_password_hash(data['newPassword'])
            try:
                res = users.update_one({'_id': ObjectId(Id)}, {'$set': {'password': Newpassword}})
            except Exception:
                abort(500)
            
        access_token = create_access_token(identity= str(user['_id']), fresh=True)
        user2 = users.find_one({'_id': ObjectId(Id)})
        response = jsonify({"msg": "update successful", 'data': json.loads(json_util.dumps(user2))})
        set_access_cookies(response, access_token)
        return  response

    else:
        resp = jsonify({'message' : 'Bad Request - invalid password'})
        resp.status_code = 400
        return resp
#user subscription 
@usersapi.route('/users/subscription/<iduser>/<idcourse>', methods=['GET'])
@jwt_required()
def subscriptionCourse(iduser, idcourse):
    
    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)
    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    user = users.find_one({'_id': ObjectId(iduser)})
    course = courses.find_one({'_id': ObjectId(idcourse)})
    # user of provier not exist in dataBase
    if user == None or course == None:
        resp = jsonify({"message": "user or course doesn't exist"})
        resp.status_code = 404
        return resp
    # Add user id to collection courses
    try:
        courses.update_one({'_id': ObjectId(idcourse)}, {'$addToSet': {"Students": ObjectId(iduser)}})
    except Exception:
        return jsonify({"message": "updte failed "})
    # Add course id to collection users
    c =[]
    c['date'] = time.strftime('%d/%m/%y', time.localtime())
    c['id'] =ObjectId(idcourse)
    try:
        users.update_one({'_id': ObjectId(iduser)}, {'$addToSet': {"courses": c}})
    except Exception:
        return jsonify({"message": "users updte failed "})    
    
    return success()
    
# get user by ID
@usersapi.route('/users/get/<iduser>/', methods=['GET'])
def getUserByID(iduser):

    cost = users.find_one({'_id': ObjectId(iduser)})
    resp = jsonify(json.loads(json_util.dumps(cost)))
    resp.status_code = 200
    return resp


# add the  favoris course  "idfavoris" to the favorites list of the user  
@usersapi.route('/users/favoris/<iduserr>/<idcourse>/', methods=['PUT'])
@jwt_required()
def userAddFavoris(iduserr, idcourse):

    if ObjectId.is_valid(iduserr) == False:
        return id_inalid(iduserr)
    if ObjectId.is_valid(idcourse) == False:
        return id_inalid(idcourse)

    user = users.find_one({'_id': ObjectId(iduserr)})
    course = courses.find_one({'_id': ObjectId(idcourse)})
    # user of provier not exist in dataBase
    if user == None or course == None:
        resp = jsonify({"message": "user or courses doesn't exist"})
        resp.status_code = 404
        return resp
    # Exist: update collection user
    try:
        users.update_one({'_id': ObjectId(iduserr)}, {'$addToSet': {"favoris": ObjectId(idcourse)}})
    except Exception:
        return jsonify({"message": "updte failed "})
    return success()

# get All user favorites
@usersapi.route('/users/favoris/<iduser>/', methods=['GET'])
@jwt_required()
def getFavoris(iduser):

    if ObjectId.is_valid(iduser) == False:
        return id_inalid()
    favoris = users.find_one({'_id': ObjectId(iduser)}, {"favoris": 1})
    # user of provier not exist in dataBase
    if favoris == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    resp = jsonify(json.loads(json_util.dumps(favoris)))
    resp.status_code = 200
    return resp

# remove idfavoris  from  favorites list
@usersapi.route('/users/favoris/delete/<iduser>/<idfavoris>', methods=['PUT'])
@jwt_required()
def userRemoveFavoris(iduser, idfavoris):

    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)
    if ObjectId.is_valid(idfavoris) == False:
        return id_inalid(idfavoris)

    user = users.find_one({'_id': ObjectId(iduser)})
    prod = courses.find_one({'_id': ObjectId(idfavoris)})
    # user of provier not exist in dataBase
    if user == None or prod == None:
        resp = jsonify({"message": "user or provider not exist"})
        resp.status_code = 404
        return resp
    
    # Exist: remove the favoris idfavoris
    try:
        users.update_one({'_id': ObjectId(iduser)}, { '$pull': {"favoris": ObjectId(idfavoris)}})
    except Exception:
       abort(500)

    return success()

# add notification to the user "iduser"
@usersapi.route('/users/notifications/add/<iduser>/', methods=['PUT'])
@jwt_required()
def userAddnotification(iduser):

    if ObjectId.is_valid(iduser) == False:
        return not_found()
    if not request.json:
        abort(400)
    if 'description' not in request.json:
        abort(400)
   
    user = users.find_one({'_id': ObjectId(iduser)})
    # user of provier not exist in dataBase
    if user == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: update collection customers
    notfication = request.get_json()
    notfication['id'] = str(uuid.uuid1())

    notfication['date'] = time.strftime('%d/%m/%y', time.localtime())
    try:
        users.update_one({'_id': ObjectId(iduser)}, {
                         '$push': {"notifications": notfication}})
    except Exception:
        message = {
            'status': 500,
            'message': 'update problem'
        }
        resp = jsonify(message)
        return resp

    return success()

# get All notifications of the user iduser
@usersapi.route('/users/notifications/<iduser>/', methods=['GET'])
@jwt_required()
def getNotifications(iduser):
  
    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)
    notifications = users.find({'_id': ObjectId(iduser)}, {"notifications": 1, '_id': 0})
    
    # user of provier not exist in dataBase
    if notifications == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    output = []
    for d in notifications:
        output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# delete all notifications
@usersapi.route('/users/notifications/deleteAll/<iduser>/', methods=['put'])
@jwt_required()
def deleteAllNotifications(iduser):

    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)

    user = users.find_one({'_id': ObjectId(iduser)})
    if user == None:
        return user_notfound(iduser)
    if 'notifications' not in user:
        return jsonify({'msg': 'There is no notification'}), 404 
    
    try:
        res = users.update_one({'_id': ObjectId(iduser)}, {'$set': {"notifications": []}})
    except Exception:
        abort(500)     

    return success()

# Delete the notification idNotification
@usersapi.route('/users/notifications/deleteOne/<idUser>/<idNotification>/', methods=['PUT'])
@jwt_required()
def deleteOneNotification(idUser, idNotification):

    if ObjectId.is_valid(idUser) == False:
        return id_inalid()
    user = users.find_one({'_id': ObjectId(idUser)})

    if user == None:
        return user_notfound(idUser)
    if 'notifications' not in user:
        return jsonify({'msg': 'There is no notification'}), 404 
    #befor selete get IDs users subscribed on this course

    try:        
        res = users.update_one({'_id': ObjectId(idUser)}, {'$pull': {"notifications": {"id": idNotification}}})
    except Exception:
        abort(500)
       
    return success()
    
#####################################################
  # Subcription
#####################################################
# get All cours where user is subscribed 
@usersapi.route('/users/orders/<iduser>/', methods=['GET'])
@jwt_required()
def getAllOrders(iduser):
  
    if ObjectId.is_valid(iduser) == False:
        return id_inalid(iduser)
    orders = users.find({'_id': ObjectId(iduser)}, {"courses": 1, '_id': 0})
    
    # user of provier not exist in dataBase
    if orders == None:
        resp = jsonify({"message": "user not exist in database"})
        resp.status_code = 404
        return resp
    # Exist: get notifications
    output = []
    for d in orders:
        output.append(json.loads(json_util.dumps(d)))
    resp = jsonify(output)
    resp.status_code = 200
    return resp

# log In 
# https://flask-jwt-extended.readthedocs.io/en/stable/refreshing_tokens/

@usersapi.route('/users/logIn/', methods=['POST'])
def login():

    if not request.json:
        abort(400)
    if 'email' not in request.json or 'password' not in request.json:
        abort(400) 

    data = request.get_json()    
    user = users.find_one({'email': data['email']})

    # Email not exist in dataBase
    if user == None:
        resp = jsonify({"message": "This Email not exist in database"})
        resp.status_code = 404
        return resp

    if check_password_hash(user['password'], data['password']):
      
        access_token = create_access_token(identity= str(user['_id']), fresh=True)
        response = jsonify({"msg": "login successful", 'data': json.loads(json_util.dumps(user))})
        set_access_cookies(response, access_token)

        return  response
        
    else:
        resp = jsonify({'message' : 'Bad Request - invalid password'})
        resp.status_code = 400
        return resp


#Logout
@usersapi.route('/users/logOut/')
def logout():
    
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response

@usersapi.route('/getAll/', methods=['GET'])
@jwt_required()
def allUsers():
    
    output = []
    for d in users.find().sort('created', -1):
        output.append(json.loads(json_util.dumps(d)))

    resp = jsonify(output)
    resp.status_code = 200
    return resp

# Using an `after_request` callback, we refresh any token that is within 30
# minutes of expiring. Change the timedeltas to match the needs of your application.
@usersapi.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response
  
  
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender='zakibrahmi@gmail.com'
    )
    mail.send(msg)
    
if __name__ == '__main__':
    app.run(debug=True)
