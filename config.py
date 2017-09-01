import json
import os


# Define the application directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Folder to store the uploaded files
UPLOAD_IMAGES_FOLDER = os.path.join(BASE_DIR, 'app/uploads/')
UPLOAD_USERIMAGES_FOLDER = os.path.join(BASE_DIR, 'app/uploads/user_images/')

# Extensions allowed for uploading to prevent XSS(Cross-Site-Scripting)
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

# Load client id for google log in
CLIENT_ID = json.loads(open('g_client_secrets.json', 'r').read())[
    'web']['client_id']
