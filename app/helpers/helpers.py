
import unicodedata
from app.models.session import session
from ..models.models import User
# extensions allowed for uploading to prevent XSS(Cross-Site-Scripting)
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


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
