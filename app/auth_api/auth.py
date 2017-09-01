import os
import httplib2
import json
import requests
import random
import string

from app.helpers.helpers import (normalize, allowed_file, get_user_id,
                                 create_user, get_user_info)

# Import flask dependencies
from flask import session as login_session
from flask import (Blueprint, render_template, request, make_response,
                   redirect, url_for, flash)

from werkzeug.utils import secure_filename

from flask_wtf.csrf import CSRFProtect

# Import module forms
from app.auth_api.forms import RegistrationForm

# Import module models (i.e. User)
from app.models.models import User
from app.models.session import session


from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from flask_httpauth import HTTPBasicAuth
from config import CLIENT_ID

from .. import app

auth = HTTPBasicAuth()

# csrf protection
csrf = CSRFProtect(app)

# Define the blueprint: 'auth', set its url prefix: app.url/auth
mod_auth = Blueprint('auth', __name__)


# register user for application
@mod_auth.route('/register', methods=['GET', 'POST'])
def user_register():
    form = RegistrationForm()
    if request.method == "POST":
        if form.validate() is False:
            flash("Invalid", 'warning')
            return render_template('register.html', form=form)
        username = form.username.data
        email = form.email.data
        password = form.password.data
        accept_tos = form.accept_tos.data

        # check if fields are empty
        if username == "" or password == "" or email == "":
            flash(
                "Arguments Missing. Make sure to enter \
                username and password to signup.", 'danger')
            return render_template('register.html', form=form)

        if (session.query(User).filter_by(
                name=username).first()
                is not None) or (session.query(User).filter_by(
                email=email).first() is not None):
            flash("That username or email is \
                already taken, please try another", 'warning')
            return render_template('register.html', form=form)

        picture = form.picture.data
        if picture and allowed_file(picture.filename):
            image_file = secure_filename(picture.filename)
            picture.save(os.path.join(
                app.config['UPLOAD_USERIMAGES_FOLDER'], image_file
            ))

        login_session['username'] = username
        login_session['email'] = email
        login_session['picture'] = normalize(picture.filename)

        user_id = get_user_id(login_session['email'])
        if not user_id and accept_tos:
            user_id = create_user(login_session)
            user = get_user_info(user_id)
            user.hash_password(password)
            session.add(user)
            session.commit()

        login_session['user_id'] = user_id
        flash("You are successfully logged in as %s" % username, 'success')
        return redirect(url_for('rest.show_categories'))

    else:
        return render_template("register.html", form=form)


# render login.html
@mod_auth.route('/login')
@csrf.exempt
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # RENDER THE LOGIN TEMPLATE
    return render_template('login.html', STATE=state)


# login normal user
@mod_auth.route('/user_login', methods=['POST'])
@csrf.exempt
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = session.query(User).filter_by(name=username).first()

        # verify password before creating login session
        if user and user.verify_password(password):
            login_session['username'] = user.name
            login_session['email'] = user.email
            login_session['user_id'] = user.id
            flash("You are successfully logged in as %s" % username, 'success')
            return redirect(url_for('rest.show_categories'))
        else:
            flash("Incorrect credentials", 'danger')
            return redirect(url_for('auth.showLogin'))


# login with google
@mod_auth.route('/gconnect', methods=['POST'])
@csrf.exempt
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
            'g_client_secrets.json', scope='', redirect_uri='postmessage')
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

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id
    flash("You are now logged in as %s" % login_session['username'], 'success')
    return "Login Successful"


# google disconnect - revoke a current user's token and reset their
# login_session
@mod_auth.route("/gdisconnect")
@csrf.exempt
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
        del login_session['user_id']

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
@mod_auth.route('/fbconnect', methods=['POST'])
@csrf.exempt
def fbconnect():
    # protection against cross site forgery attack
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameters.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode('utf8')

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
    token = data['access_token']

    url = ("https://graph.facebook.com/v2.10/me?"
           "access_token=%s&fields=name,id,email") % token
    h = httplib2.Http()
    req = h.request(url, 'GET')[1]
    req_json = req.decode('utf8').replace("'", '"')
    data = json.loads(req_json)

    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session["facebook_id"] = data["id"]

    # Get user picture
    url = ("https://graph.facebook.com/v2.10/me/picture?"
           "access_token=%s&redirect=0&height=200&width=200") % token
    h = httplib2.Http()
    req = h.request(url, 'GET')[1]
    req_json = req.decode('utf8').replace("'", '"')
    data = json.loads(req_json)

    login_session['picture'] = data["data"]["url"]

    # see if user exists, if no, then create a new user
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id
    flash("You are now logged in as %s" % login_session['username'], 'success')
    return "Login Successful"


# facebook disconnect
@mod_auth.route('/fbdisconnect')
@csrf.exempt
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
@mod_auth.route('/disconnect')
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

        flash("You have successfully been logged out.", 'success')
        return redirect(url_for('rest.show_categories'))
    else:
        del login_session["username"]
        del login_session["email"]
        del login_session["user_id"]
        flash("You have successfully been logged out.", 'success')
        return redirect(url_for('rest.show_categories'))
