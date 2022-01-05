#https://github.com/winstonmhango23/flask-mail-confirm-reset2
from flask import Flask, render_template,  request, redirect, url_for, flash

##########################
#### importing flask extensions ####
##########################
from flask_mail import Mail, Message
from threading import Thread
from itsdangerous import URLSafeTimedSerializer
from flask_bcrypt import Bcrypt
from datetime import datetime
from forms import RegisterForm, LoginForm, ResetEmailForm,ResetPasswordForm
from flask import Flask, Blueprint, jsonify, make_response, abort, request

# from .forms import RegisterForm, LoginForm


#create the object of Flask
app  = Flask(__name__)
##########################
#### flask app configurations ####
##########################
app.config['SECRET_KEY'] = 'hardsecretkey'

#Email related Configuration values
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'codesnnippetstests@gmail.com'
app.config['MAIL_PASSWORD'] = '@Codesnnippetstests2021'
app.config['MAIL_DEFAULT_SENDER'] = 'codesnnippetstests@gmail.com'
from . import *

##########################
#### initialising flask extensions ####
##########################
usersapi = Blueprint(name="usersapi", import_name=__name__)

# traitement erreur
@usersapi.errorhandler(400)
def create_failed(error):
    return make_response(jsonify({"error": "bad input"}), 400)

@usersapi.errorhandler(500)
def internalServer(error):
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)

mail = Mail(app)
bcrypt = Bcrypt(app)


##########################
#### defining user model and its helper functions using sqlalchemy ####
##########################

##########################
####mail sending,confirmation and password hashing helper functions ####
##########################

def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), 'info')


def send_async_email(msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, html_body):
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()


def send_confirmation_email(user_email):
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    confirm_url = url_for(
        'confirm_email',
        token=confirm_serializer.dumps(user_email, salt='email-confirmation-salt'),
        _external=True)

    html = render_template(
        'email_confirmation.html',
        confirm_url=confirm_url)

    send_email('Confirm Your Email Address', [user_email], html)


def send_password_reset_link(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    password_reset_url = url_for(
        'token_reset',
        token = password_reset_serializer.dumps(user_email, salt='password-reset-salt'),
        _external=True)

    html = render_template(
        'email_reset.html',
        password_reset_url=password_reset_url)

    send_email('Password Reset Requested', [user_email], html)

################
#### routes ####
################
@app.route('/')
def home():
    form = LoginForm(request.form)
    return render_template('login.html', form=form)


# email confirmation and activationm route functions
"""
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=86400)
    except:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        user.email_confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Thank you for confirming your email address!', 'success')

    return redirect(url_for('blog'))
"""
#reset_email password route
@app.route('/reset', methods=["GET", "POST"])
def reset_email():
    
    if not request.json:
        abort(400)
    if 'email' not in request.json:
        abort(400) 

    data = request.get_json()    
    
    try:
        user = users.find_one({'email': data['email']})
    except:
        return internalServer()
    
    if user == None: 
        resp = jsonify({"message": "Invialide email"})
        resp.status_code = 404
        return resp

    send_password_reset_link(user.email)
    resp = jsonify({"message": "link sent"})
    resp.status_code = 200
    return resp

@app.route('/reset/<token>', methods=["GET", "POST"])
def token_reset(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    

    form = ResetPasswordForm()

    if form.validate_on_submit():
        try:
            user =  users.find_one({'email': email})
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('login'))

        user._password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token_pass.html',token=token, form=form)


#run flask app
if __name__ == "__main__":
    app.run(debug=True)
