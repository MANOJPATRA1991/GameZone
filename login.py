import os
import httplib2
import json
import requests
import random
import string
import unicodedata

from flask import Flask, g
from flask import session as login_session
from flask import (render_template, request, make_response,
                   redirect, url_for, flash, jsonify, send_from_directory)

from flask_wtf import FlaskForm
from flask_uploads import UploadSet, IMAGES, configure_uploads
from flask_wtf.file import FileField, FileAllowed, FileRequired, DataRequired
from werkzeug.utils import secure_filename

from wtforms import (StringField, TextField, SubmitField, SelectField, TextAreaField)
from wtforms import validators, ValidationError

from sqlalchemy import create_engine, update, asc
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Category, Games

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()
# create an instance of the Flask class
app = Flask(__name__)

# folder to store the uploaded files
app.config['UPLOAD_IMAGES_FOLDER'] = 'uploads/'
# extensions allowed for uploading to prevent XSS(Cross-Site-Scripting)
app.config['ALLOWED_EXTENSIONS'] = set(['png', 'jpg', 'jpeg'])
# configure_uploads(app, (images))
engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']


class CreateForm(FlaskForm):
    name = TextField("Name", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    image = FileField('Image', validators=[
                        FileRequired()
                    ])

    youtubeVideoURL = TextField("Trailer on Youtube",
                                    validators=[DataRequired()])
    category = SelectField('Genre',
                        choices=[('1', 'Action'),
                                 ('2', 'Action-Adventure'),
                                 ('3', 'Adventure'),
                                 ('4', 'Role-playing'),
                                 ('5', 'Simulation'),
                                 ('6', 'Sports'),
                                 ('7', 'Strategy')])

    submit = SubmitField("Create")


# ------------------------------------------------------------
#            USER AUTHENTICATION AND AUTHORIZATION
# ------------------------------------------------------------


@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# render login.html
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # RENDER THE LOGIN TEMPLATE
    return render_template('login.html', STATE=state)


# login with google
@app.route('/gconnect', methods=['POST'])
def gconnect():

    # check for cross-site request forgery
    if request.args.get('state') != login_session['state']:
        # creates a response with a 401 error code
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # code from the authorization server redirection sent by the client
    code = request.data
    try:
        # create a Flow object
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='', redirect_uri='postmessage')
        # one-time-code flow that our server will be sending off

        # exchanges the authorization code for a Credentials object
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access_token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)

    h = httplib2.Http()

    # get the content from this link
    req = h.request(url, 'GET')[1]
    req_json = req.decode('utf8').replace("'", '"')
    result = json.loads(req_json)
    print(result)
    if result.get('error') is not None:
        # internal server error
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that access token is for the intended user
    # by using sub as the unique identifier key
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID does not match app's."))
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # check to see if a user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # store the access token in the session for later use
    login_session['provider'] = "google"
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # see if user exists, if no, then create a new user
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id
    # login_session['token'] = user.generate_auth_token(600)
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    return output


# google disconnect - revoke a current user's token and reset their
# login_session
@app.route("/gdisconnect")
def gdisconnect():
    # Only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET request to revoke current token
    access_token = credentials
    url = "https://accounts.google.com/o/oauth2/revoke?token=%s" % access_token

    h = httplib2.Http()

    # get the resp_headers from this link
    result = h.request(url, 'GET')[0]
    print(result)
    if result['status'] == '200':
        # Reset the user's session
        del login_session['username']
        del login_session['picture']
        del login_session['email']

        response = make_response(json.dumps("Successfully disconnected."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid
        response = make_response(json.dumps(
            "Failed to revoke token for given user,"), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# login with facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # protection against cross site forgery attack
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameters.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode('utf8')
    print("access token received %s " % access_token)

    # Exchange client token for long-lived server side token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_secret']
    url = ('https://graph.facebook.com/v2.10/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)

    h = httplib2.Http()
    req = h.request(url, 'GET')[1]
    print(req)
    req_json = req.decode('utf8').replace("'", '"')
    data = json.loads(req_json)
    # use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.10/me"
    token = data['access_token']

    url = "https://graph.facebook.com/v2.10/me?access_token=%s&fields=name,id,email" % token
    h = httplib2.Http()
    req = h.request(url, 'GET')[1]
    req_json = req.decode('utf8').replace("'", '"')
    data = json.loads(req_json)

    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session["facebook_id"] = data["id"]

    # Get user picture
    url = "https://graph.facebook.com/v2.10/me/picture?access_token=%s&redirect=0&height=200&width=200" % token
    h = httplib2.Http()
    req = h.request(url, 'GET')[1]
    req_json = req.decode('utf8').replace("'", '"')
    data = json.loads(req_json)

    login_session['picture'] = data["data"]["url"]

    # see if user exists, if no, then create a new user
    user_id=get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    login_session['token'] = user.generate_auth_token(600)
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: ' \
              '150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    return output


# facebook disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session["facebook_id"]
    url = "https://graph.facebook.com/%s/permissions" % facebook_id

    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session["username"]
    del login_session["email"]
    del login_session["picture"]
    del login_session["user_id"]
    return "You have been logged out"


# log out user
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['credentials']
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session["facebook_id"]

        del login_session['provider']

        flash("You have successfully been logged out.")
        return redirect(url_for('show_categories'))
    else:
        flash("You are not logged in to begin with.")
        return redirect(url_for('show_categories'))