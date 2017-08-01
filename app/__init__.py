from flask import Flask

from flask_httpauth import HTTPBasicAuth

from config import UPLOAD_IMAGES_FOLDER, UPLOAD_USERIMAGES_FOLDER


auth = HTTPBasicAuth()

# create an instance of the Flask class
app = Flask(__name__)

# Import a module / component using its blueprint handler variable
from .auth_api.auth import mod_auth as auth_module
from .json_api.json import json_api as json_module
from .rest_api.rest_api import rest_api as rest_module

# Register blueprint(s)
app.register_blueprint(auth_module)
app.register_blueprint(json_module)
app.register_blueprint(rest_module)

app.config.from_object('config')

# folder to store the uploaded files
app.config['UPLOAD_IMAGES_FOLDER'] = UPLOAD_IMAGES_FOLDER
app.config['UPLOAD_USERIMAGES_FOLDER'] = UPLOAD_USERIMAGES_FOLDER
