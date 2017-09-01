import os
from .. import app
from flask import (Blueprint, render_template, flash,
                   redirect, url_for, request, make_response,
                   json, abort, send_from_directory)
from app.models.models import Category, Games
from app.models.session import session
from sqlalchemy import asc

from flask import session as login_session

from werkzeug.utils import secure_filename

from app.helpers.helpers import (normalize, allowed_file,
                                 check_admin, embed_link)

from ..auth_api.forms import CreateForm

rest_api = Blueprint('rest', __name__)


# show all categories
@rest_api.route('/')
@rest_api.route('/category/')
def show_categories():
    """Return the rendered template for categories.

    Returns: Rendered html template
    """
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('categories.html', categories=categories)


# show games for a particular category
@rest_api.route('/category/<int:category_id>/')
@rest_api.route('/category/<int:category_id>/games/')
def show_games_by_category(category_id):
    """Return the rendered template for categories filtered by category.

    Args:
        category_id(int)

    Returns: Rendered html template

    """
    admin = False
    if 'username' not in login_session:
        user_id = None
    else:
        user_id = login_session['user_id']
        # check if user is admin
        admin = check_admin(user_id)
    category = session.query(Category).filter_by(id=category_id).one()
    games = session.query(Games).filter_by(category_id=category_id).all()
    return render_template('show_games_by_category.html',
                           category=category,
                           games=games, user_id=user_id, admin=admin)


# show all games
@rest_api.route('/games/')
def show_games():
    """Return the rendered template for games.

    Returns: Rendered html template

    """
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
@rest_api.route('/games/<int:game_id>')
def show_game(game_id):
    """Return the rendered template for a game with game_id.

    Args:
        game_id(int)

    Returns: Rendered html template

    """
    game = session.query(Games).filter_by(id=game_id).one()
    date = game.release_date.date().strftime("%d, %B %Y")
    category = session.query(Category).filter_by(id=game.category_id).one()
    return render_template('game_page.html',
                           game=game,
                           category=category,
                           date=date,
                           embed_link=embed_link(game.video_path))


# Create new game data
@rest_api.route('/games/new/', methods=['GET', 'POST'])
def new_game():
    """Creates a new game entry in the database.

    Returns: Rendered html template or redirect url
    """
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
        return redirect(url_for('rest.show_games'))
    else:
        return render_template('new_game.html',
                               form=form)


# Edit a game's data
@rest_api.route('/games/<int:game_id>/edit', methods=['GET', 'POST'])
def edit_game(game_id):
    """Allows user to edit a game.

    Args:
        game_id(int)

    Returns: Rendered html template or redirect url

    """
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
            return redirect(url_for('rest.show_games'))
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
@rest_api.route('/games/<int:game_id>/delete', methods=['GET', 'POST'])
def delete_game(game_id):
    """Allows user to delete a game.

    Args:
        game_id(int)

    Returns: Rendered html template or redirect url

    """
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
            os.remove(os.path.join(
                app.config['UPLOAD_IMAGES_FOLDER'],
                game.image_path
            ))
            os.remove(os.path.join(
                app.config['UPLOAD_IMAGES_FOLDER'],
                game.banner_path
            ))
            flash('Game Data Successfully Deleted', 'success')
            return redirect(url_for('rest.show_games'))
        else:
            return render_template('delete_game.html', game=game, form=form)
    else:
        response = make_response(json.dumps('You are not authorized \
                                            to perform the operation'), 401)
        abort(response)


# See images on a tab in the browser
@rest_api.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Allows user to view images on a new tab in the browser.

    Args:
        filename(path)

    Returns: Image file

    """
    return send_from_directory(app.config['UPLOAD_IMAGES_FOLDER'],
                               filename)
