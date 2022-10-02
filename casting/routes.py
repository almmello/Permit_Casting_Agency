from flask import (
    Blueprint, request, abort, jsonify
)

from casting.models import Actors, Movies
from .auth import requires_auth


bp = Blueprint('routes', __name__)

@bp.route('/actors', methods=['GET'], endpoint='get_actors')
@requires_auth('read', 'actors')
def read_all_actors(jwt):

    # using the try-except method to create the query
    try:

        # create the query actors order by id
        query_actors = Actors.query.all()

        # check if the query has no results and abort
        if len(query_actors) == 0:
            abort(404)

        # if has results, return them
        else:

            return jsonify({
                'success': True,
                'actors': [actor.read() for actor in query_actors]
            })

    # if the query fails, abort
    except:
        abort(404)

'''
@bp.route('/actors', methods=['POST'], endpoint='post_actor')
@requires_auth('create', 'actors')
def create_actor(jwt):

    # create the data JSON object
    data = request.get_json()

    # use the try-except method to insert the data
    try:
        new_actor = Actors(
            name = data.get('name'),
            age = data.get('age'),
            gender = data.get('gender')
        )

        new_actor.insert()

        # return the data
        return jsonify({
            'success': True,
            'actors': [new_actor.read()]
        })

    # if insert fails, abort
    except:
        abort(400)

@bp.route('/actors/<id>', methods=['PATCH'])
@requires_auth('patch:actors')
def update_actor(jwt, id):

    # retrieve data from request to update the actor
    data = request.get_json()
    id_update = int(id)
    name_update = data.get('name')
    age_update = data.get('age')
    gender_update = data.get('gender')

    # use the try-except method to insert the data
    try:

        # create the query drink using requested id
        query_actors = Actors.query.get(id_update)

        # update query title and recipe
        query_actors.name = name_update
        query_actors.age = age_update
        query_actors.gender = gender_update

        # if the query drink is not empty, update the drink
        if query_actors is not None:

            query_actors.update()

            # return the JSON object with the long drink
            return jsonify({
                'success': True,
                'actors': [query_actors.read()]
            })

        # if there are no results, abort
        else:
            abort(404)

    # if the query fails, abort
    except:
        abort(422)

@bp.route('/actors/<int:id>', methods=['DELETE'])
@requires_auth('delete:actors')
def delete_actor(jwt, id):

    # using the try-except method to delete the movie
    try:

        # create the query drinks with the the id
        query_actors = Actors.query.get(id)

        # if the drink is not empty, delete the drink
        if query_actors is not None:
            query_actors.delete()

            # return the JSON object with the long drink
            return jsonify({
                'success': True,
                'delete': id
            })

        # if the quere is empty, abort
        else:
            abort(404)

    # if the query fails, abort
    except Exception:
        abort(404)

# Movies routes

@bp.route('/movies', methods=['GET'], endpoint='get_movies')
@requires_auth('get:movies')
def read_all_movies(jwt):

    # using the try-except method to create the query
    try:

        # create the query movies order by id
        query_movies = Movies.query.all()

        # check if the query has no results and abort
        if len(query_movies) == 0:
            abort(404)

        # if has results, return them
        else:

            return jsonify({
                'success': True,
                'movies': [movie.read() for movie in query_movies]
            })

    # if the query fails, abort
    except:
        abort(404)




@bp.route('/movies', methods=['POST'], endpoint='post_movie')
@requires_auth('post:movies')
def create_movie(jwt):

    # create the data JSON object
    data = request.get_json()

    # use the try-except method to insert the data
    try:
        new_movie = Movies(
            title = data.get('title'),
            release_date = data.get('release_date')
        )

        new_movie.insert()

        # return the data
        return jsonify({
            'success': True,
            'movies': [new_movie.read()]
        })

    # if insert fails, abort
    except:
        abort(400)



@bp.route('/movies/<id>', methods=['PATCH'])
@requires_auth('patch:movies')
def update_movie(jwt, id):

    # retrieve data from request to update the movie
    data = request.get_json()
    id_update = int(id)
    title_update = data.get('title')
    release_date_update = data.get('release_date')

    # use the try-except method to insert the data
    try:

        # create the query drink using requested id
        query_movies = Movies.query.get(id_update)

        # update query title and recipe
        query_movies.title = title_update
        query_movies.release_date = release_date_update

        # if the query drink is not empty, update the drink
        if query_movies is not None:

            query_movies.update()

            # return the JSON object with the long drink
            return jsonify({
                'success': True,
                'movies': [query_movies.read()]
            })

        # if there are no results, abort
        else:
            abort(404)

    # if the query fails, abort
    except:
        abort(422)


@bp.route('/movies/<int:id>', methods=['DELETE'])
@requires_auth('delete:movies')
def delete_movie(jwt, id):

    # using the try-except method to delete the movie
    try:

        # create the query drinks with the the id
        query_movies = Movies.query.get(id)

        # if the drink is not empty, delete the drink
        if query_movies is not None:
            query_movies.delete()

            # return the JSON object with the long drink
            return jsonify({
                'success': True,
                'delete': id
            })

        # if the quere is empty, abort
        else:
            abort(404)

    # if the query fails, abort
    except Exception:
        abort(404)

'''

