import json

# folder to store the uploaded files
UPLOAD_IMAGES_FOLDER = 'uploads/'
UPLOAD_USERIMAGES_FOLDER = 'uploads/user_images/'
# extensions allowed for uploading to prevent XSS(Cross-Site-Scripting)
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


# load client id for google log in
CLIENT_ID = json.loads(open('g_client_secrets.json', 'r').read())[
    'web']['client_id']
