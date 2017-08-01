from flask import Blueprint
from ..models.models import Category, Games
from ..models.session import session
from flask import jsonify

json_api = Blueprint('json', __name__)


# list all categories available
@json_api.route('/category/JSON')
def category_json():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# list games belonging to a particular category in json format
@json_api.route('/category/<int:category_id>/games/JSON')
def games_by_category_json(category_id):
    games = session.query(Games).filter_by(
        category_id=category_id).all()
    return jsonify(Games=[game.serialize for game in games])


# list a particular game based on a id in json format
@json_api.route('/games/<int:game_id>/JSON')
def game_json(game_id):
    game = session.query(Games).filter_by(id=game_id).first()
    if game is not None:
        return jsonify(Games=game.serialize)
    else:
        return jsonify("No results found")


# list all games in JSON format
@json_api.route('/games/JSON')
def games_json():
    games = session.query(Games).all()
    return jsonify(Games=[game.serialize for game in games])
