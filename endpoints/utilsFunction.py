
from flask import jsonify

from flask_pymongo import PyMongo
import os
from flask import Flask, request, make_response
import re
import json
import jwt
from flask.json import jsonify
from bson.objectid import ObjectId
from . import *

"""
from exponent_server_sdk import (
    DeviceNotRegisteredError,
    PushClient,
    PushMessage,
    PushServerError,
)
"""
app = Flask(__name__)

 

def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)
    
def id_inalid(id):
    message = {
               'status': 403,
               'message': 'Id invalid: ' + id,
             }
    resp = jsonify(message)
    return resp
    
def success():
    message = {
               'status': 200,
               'message': "success"
             }        
    resp = jsonify(message)
    return resp

#JWT
def token_required(f):
   
   def decorator(*args, **kwargs):
       token = None
       if 'x-api-key' in request.headers:
           token = request.headers['x-api-key']
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
          data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
          current_user = users.find_one({'_id': ObjectId(data['_id'])})
       except:
          return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator

# function for verifying the access token
def token_required_admin(data):
      token = None
        # jwt is passed in the request header
      if 'Authorization' in data:
            token = data['Authorization']
        # return 401 if token is not passed
      else: 
        return "Token is missing !!"
      #split tokne to: Bearer firebaseId phone/Email
      g = re.match("^Bearer\s+(.*)", token)

      if not g:
        return "invalid Token" 
      token =  g.group(1)
      w = token.split()

      try:
           user = users.find_one({'oidFirebase': w[0]})
      except:
          return "internal server problem !!" 
      if user == None:
        return "Access Denied" 
      return "authorized"


# function for verifying the access token
"""
def token_required2(data):
      token = None
        # jwt is passed in the request header
      if 'Authorization' in data:
            token = data['Authorization']
        # return 401 if token is not passed
      else: 
        return "Token is missing !!"
      #split tokne to: Bearer firebaseId phone/Email
      g = re.match("^Bearer\s+(.*)", token)

      if not g:
        return "invalid Token" 
      token =  g.group(1)
      w = token.split()
      
      #check firebase and email/mobile
      filter =""
      if check(w[1]) =="email":
        filter = "email"
      else:
        filter="mobile"
      try:
           user = customers.find_one({'oidFirebase': w[0], filter: w[1] })
      except:
          return "internal server problem !!" 
      if user == None:
        return "Access Denied" 
      return "authorized"



# Define a function for
# for validating an Email 
 
def check(email):
  regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
  # pass the regular expression
  # and the string in search() method
  if(re.match(regex, email)):
    return 'email' 
  else:
    return  'phone'   
"""   
"""
def send_push_message(token, title, message, extra=None):
    try:
        response = PushClient().publish(
            PushMessage(to=token,
                        title=title,
                        body=message,
                        channel_id="Ads",
                        data=extra))
    except PushServerError as exc:
        internalServer()
        raise
    except (ConnectionError, HTTPError) as exc:
        internalServer()
    try:
        # We got a response back, but we don't know whether it's an error yet.
        # This call raises errors so we can handle them with normal exception
        # flows.
        response.validate_response()
    except DeviceNotRegisteredError:
        internalServer()
        # Mark the push token as inactive
    #     from notifications.models import PushToken
    #     PushToken.objects.filter(token=token).update(active=False)
    # except PushTicketError as exc:
    #   """  