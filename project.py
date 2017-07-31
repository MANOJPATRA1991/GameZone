import os
import httplib2
import json
import requests
import random
import string
import unicodedata

from flask import Flask
from flask import session as login_session
from flask import (render_template, request, make_response,
                   redirect, url_for, flash, jsonify,
                   send_from_directory, abort)

from flask_wtf import FlaskForm

from flask_wtf.csrf import CSRFProtect

from flask_wtf.file import FileField, FileRequired, DataRequired

from werkzeug.utils import secure_filename

from wtforms import (DateField, TextField,
                     SubmitField, SelectField, TextAreaField,
                     BooleanField, PasswordField)

from wtforms import validators

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Category, Games

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

# create an instance of the Flask class
app = Flask(__name__)

# folder to store the uploaded files
UPLOAD_IMAGES_FOLDER = 'uploads/'
UPLOAD_USERIMAGES_FOLDER = 'uploads/user_images/'
app.config['UPLOAD_IMAGES_FOLDER'] = UPLOAD_IMAGES_FOLDER
app.config['UPLOAD_USERIMAGES_FOLDER'] = UPLOAD_USERIMAGES_FOLDER
# extensions allowed for uploading to prevent XSS(Cross-Site-Scripting)
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# load client id for google log in
CLIENT_ID = json.loads(open('g_client_secrets.json', 'r').read())[
    'web']['client_id']

# csrf protection
csrf = CSRFProtect(app)


# Create form for User Registration
class RegistrationForm(FlaskForm):
    username = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [
                             validators.DataRequired(),
                             validators.EqualTo('confirm',
                                                message='Passwords must match')
                             ])

    picture = FileField('Image', validators=[
        FileRequired()
    ])

    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the Terms of Service and \
                              Privacy Notice (updated Jul 31, 2017)',
                              [validators.DataRequired()])

    submit = SubmitField("Register")


# Create form for CRUD operations
class CreateForm(FlaskForm):
    name = TextField("Name", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    image = FileField('Image', validators=[
        FileRequired()
    ])
    banner = FileField('Image', validators=[
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

    platform = SelectField('Platform',
                           choices=[('Playstation', 'Playstation'),
                                    ('XBox', 'XBox'),
                                    ('PC', 'PC')])

    creators = TextField('Creators', validators=[DataRequired()])

    release_date = DateField('Release Date', format='%m/%d/%Y')

    submit = SubmitField("Create")


# ------------------------------------------------------------
#            USER AUTHENTICATION AND AUTHORIZATION
# ------------------------------------------------------------

# register user for application
@app.route('/register', methods=['GET', 'POST'])
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
        return redirect(url_for('show_categories'))

    else:
        return render_template("register.html", form=form)


# render login.html
@app.route('/login')
@csrf.exempt
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # RENDER THE LOGIN TEMPLATE
    return render_template('login.html', STATE=state)


# login normal user
@app.route('/user_login', methods=['POST'])
@csrf.exempt
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = session.query(User).filter_by(name=username).first()
        if user and user.verify_password(password):
            login_session['username'] = user.name
            login_session['email'] = user.email
            login_session['user_id'] = user.id
            flash("You are successfully logged in as %s" % username, 'success')
            return redirect(url_for('show_categories'))
        else:
            flash("Incorrect credentials", 'danger')
            return redirect(url_for('showLogin'))


# login with google
@app.route('/gconnect', methods=['POST'])
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
@app.route("/gdisconnect")
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
@app.route('/fbconnect', methods=['POST'])
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
@app.route('/fbdisconnect')
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

        flash("You have successfully been logged out.", 'success')
        return redirect(url_for('show_categories'))
    else:
        del login_session["username"]
        del login_session["email"]
        del login_session["user_id"]
        flash("You have successfully been logged out.", 'success')
        return redirect(url_for('show_categories'))


# ------------------------------------------------------------
#                       REST APIs FOR APP
# ------------------------------------------------------------

# list all categories available
@app.route('/category/JSON')
def category_json():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# list games belonging to a particular category in json format
@app.route('/category/<int:category_id>/games/JSON')
def games_by_category_json(category_id):
    games = session.query(Games).filter_by(
        category_id=category_id).all()
    return jsonify(Games=[game.serialize for game in games])


# list a particular game based on a id in json format
@app.route('/games/<int:game_id>/JSON')
def game_json(game_id):
    game = session.query(Games).filter_by(id=game_id).first()
    if game is not None:
        return jsonify(Games=game.serialize)
    else:
        return jsonify("No results found")


# list all games in JSON format
@app.route('/games/JSON')
def games_json():
    games = session.query(Games).all()
    return jsonify(Games=[game.serialize for game in games])


# show all categories
@app.route('/')
@app.route('/category/')
def show_categories():
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('categories.html', categories=categories)


# show games for a particular category
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/games/')
def show_games_by_category(category_id):
    admin = False
    if 'username' not in login_session:
        user_id = None
    else:
        user_id = login_session['user_id']
        admin = check_admin(user_id)
    category = session.query(Category).filter_by(id=category_id).one()
    games = session.query(Games).filter_by(category_id=category_id).all()
    return render_template('show_games_by_category.html',
                           category=category,
                           games=games, user_id=user_id, admin=admin)


# show all games
@app.route('/games/')
def show_games():
    admin = False
    if 'username' not in login_session:
        user_id = None
    else:
        user_id = login_session['user_id']
        admin = check_admin(user_id)
    games = session.query(Games).all()
    return render_template('games.html',
                           games=games,
                           user_id=user_id,
                           admin=admin)


# show a game with id
@app.route('/games/<int:game_id>')
def show_game(game_id):
    game = session.query(Games).filter_by(id=game_id).one()
    date = game.release_date.date().strftime("%d, %B %Y")
    category = session.query(Category).filter_by(id=game.category_id).one()
    return render_template('game_page.html',
                           game=game,
                           category=category,
                           date=date,
                           embed_link=embed_link(game.video_path))


# Create new game data
@app.route('/games/new/', methods=['GET', 'POST'])
def new_game():
    form = CreateForm()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if form.validate() is False:
            flash('All fields are required.', 'warning')
        name = normalize(form.name.data)
        game = session.query(Games).filter_by(name=name).first()
        if game is not None:
            flash('Game already exists in the database', 'warning')
            return render_template('new_game.html',
                                   form=form)
        description = normalize(form.description.data)

        image_path = form.image.data
        if image_path and allowed_file(image_path.filename):
            image_file = secure_filename(image_path.filename)
            image_path.save(os.path.join(
                app.config['UPLOAD_IMAGES_FOLDER'], image_file
            ))

        banner_path = form.banner.data
        if banner_path and allowed_file(banner_path.filename):
            banner_file = secure_filename(banner_path.filename)
            banner_path.save(os.path.join(
                app.config['UPLOAD_IMAGES_FOLDER'], banner_file
            ))

        platform = normalize(form.platform.data)
        creators = normalize(form.creators.data)
        release_date = form.release_date.data
        video_path = normalize(form.youtubeVideoURL.data)
        category_id = normalize(form.category.data)

        new_game = Games(name=name,
                         description=description,
                         image_path=normalize(image_path.filename),
                         banner_path=normalize(banner_path.filename),
                         platform=platform,
                         creators=creators,
                         release_date=release_date,
                         video_path=video_path,
                         category_id=category_id,
                         user_id=login_session['user_id'])
        session.add(new_game)
        session.commit()
        flash('New game data for ' + new_game.name + ' created!!', 'success')
        return redirect(url_for('show_games'))
    else:
        return render_template('new_game.html',
                               form=form)


# Edit a game's data
@app.route('/games/<int:game_id>/edit', methods=['GET', 'POST'])
def edit_game(game_id):
    if 'username' not in login_session:
        return redirect('/login')
    edited_game = session.query(Games).filter_by(id=game_id).first()
    if (edited_game is not None and (edited_game.user_id ==
                                     login_session['user_id']
                                     ) or check_admin(
            login_session['user_id'])):
        date_to_edit = edited_game.release_date.date().strftime("%d/%m/%y")
        form = CreateForm(category=edited_game.category_id,
                          platform=edited_game.platform)
        if request.method == 'POST':
            if form.name.data:
                edited_game.name = normalize(form.name.data)
            if form.description.data:
                edited_game.description = normalize(form.description.data)
            if form.image.data:
                image_path = form.image.data
                if image_path and allowed_file(image_path.filename):
                    image_file = secure_filename(image_path.filename)
                    os.remove(os.path.join(
                        app.config['UPLOAD_IMAGES_FOLDER'],
                        edited_game.image_path
                    ))
                    image_path.save(os.path.join(
                        app.config['UPLOAD_IMAGES_FOLDER'], image_file
                    ))
                edited_game.image_path = normalize(image_path.filename)
            if form.banner.data:
                banner_path = form.banner.data
                if banner_path and allowed_file(banner_path.filename):
                    banner_file = secure_filename(banner_path.filename)
                    os.remove(os.path.join(
                        app.config['UPLOAD_IMAGES_FOLDER'],
                        edited_game.banner_path
                    ))
                    banner_path.save(os.path.join(
                        app.config['UPLOAD_IMAGES_FOLDER'], banner_file
                    ))
                edited_game.banner_path = normalize(banner_path.filename)
            if form.youtubeVideoURL.data:
                edited_game.video_path = normalize(form.youtubeVideoURL.data)
            if form.category.data:
                edited_game.category_id = normalize(form.category.data)
            if form.platform.data:
                edited_game.platform = normalize(form.platform.data)
            if form.creators.data:
                edited_game.creators = normalize(form.creators.data)
            if form.release_date.data:
                edited_game.release_date = normalize(form.release_date.data)
            print(edited_game.name)
            session.add(edited_game)
            session.commit()
            flash('Game data for ' + edited_game.name +
                  ' edited and saved successfully!!', 'success')
            return redirect(url_for('show_games'))
        else:
            return render_template('edit_game.html',
                                   form=form,
                                   date_to_edit=date_to_edit,
                                   game=edited_game)
    else:
        response = make_response(json.dumps('You are not authorized \
                                            to perform the operation'), 401)
        abort(response)


# Delete a game
@app.route('/games/<int:game_id>/delete', methods=['GET', 'POST'])
def delete_game(game_id):
    form = CreateForm()
    if 'username' not in login_session:
        return redirect('/login')
    game = session.query(Games).filter_by(id=game_id).first()
    if (game is not None and (game.user_id ==
                              login_session['user_id']
                              ) or check_admin(login_session['user_id'])):
        if request.method == 'POST':
            session.delete(game)
            session.commit()
            flash('Game Data Successfully Deleted', 'success')
            return redirect(url_for('show_games'))
        else:
            return render_template('delete_game.html', game=game, form=form)
    else:
        response = make_response(json.dumps('You are not authorized \
                                            to perform the operation'), 401)
        abort(response)


# See images on a tab in the browser
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_IMAGES_FOLDER'],
                               filename)


# ------------------------------------------------------------
#                       HELPER METHODS
# ------------------------------------------------------------
# check if user is admin
def check_admin(user_id):
    if get_user_info(user_id).admin:
        return True
    else:
        return False


# get user based on email
def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# get user bades on user-id
def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# create user
def create_user(login_session):
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# normalize to ascii
def normalize(val):
    return unicodedata.normalize(
        'NFKD', val).encode('ascii', 'ignore')


# check if uploaded file is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# convert youtube link to embed format
def embed_link(video):
    url = video
    print(url)
    url = url.replace("watch?v=", "embed/")
    return url


# run if execution is through a python interpreter
if __name__ == "__main__":
    # secret key
    app.secret_key = open('secret_key', 'r').read()
    # to enable just the interactive debugger without the code reloading
    app.debug = True
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
