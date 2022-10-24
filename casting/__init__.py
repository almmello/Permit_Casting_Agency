import os
from flask import Flask, request, jsonify, abort, redirect, render_template, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
#from .auth import AuthError, requires_auth



from dotenv import load_dotenv

from functools import wraps
import json
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth

from jose import jwt
from urllib.request import urlopen

from permit.sync import Permit

load_dotenv()  # take environment variables from .env.

permit = Permit(
    # in production, you might need to change this url to fit your deployment
    pdp=os.getenv("PERMIT_PDP"),
    # your api key
    token=os.getenv("PERMIT_TOKEN"),
)

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
ALGORITHMS = ['RS256']
API_AUDIENCE = os.getenv("AUTH0_CLIENT_ID")


db = SQLAlchemy()
migrate = Migrate()

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY = os.getenv("APP_SECRET_KEY"),
        #SQLALCHEMY_DATABASE_URI = 'sqlite:///{}'.format(os.path.join(os.path.dirname(__file__), 'app.db')),
        #SQLALCHEMY_DATABASE_URI = os.environ.get('POSTGRES_URL') or 'sqlite:///' + os.path.join(app.instance_path, 'casting.sqlite'),
        SQLALCHEMY_DATABASE_URI = 'postgresql://postgres@localhost:5432/casting',
        SQLALCHEMY_TRACK_MODIFICATIONS = False
    )

    CORS(app)

    # CORS Headers
    @app.after_request
    def after_request(response):
        response.headers.add(
            "Access-Control-Allow-Headers", "Content-Type, Authorization, true"
        )
        response.headers.add(
            "Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS"
        )
        return response

    db.init_app(app)
    migrate.init_app(app, db)


    oauth = OAuth(app)

    oauth.register(
        "auth0",
        client_id=os.getenv("AUTH0_CLIENT_ID"),
        client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration'
    )


    def verify_decode_jwt(token):
        jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        if 'kid' not in unverified_header:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Authorization malformed.'
            }, 401)

        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer='https://' + AUTH0_DOMAIN + '/'
                )

                return payload

            except jwt.ExpiredSignatureError:
                raise AuthError({
                    'code': 'token_expired',
                    'description': 'Token expired.'
                }, 401)

            except jwt.JWTClaimsError:
                raise AuthError({
                    'code': 'invalid_claims',
                    'description': 'Incorrect claims. Please, check the audience and issuer.'
                }, 401)
            except Exception:
                raise AuthError({
                    'code': 'invalid_header',
                    'description': 'Unable to parse authentication token.'
                }, 400)
        raise AuthError({
                    'code': 'invalid_header',
                    'description': 'Unable to find the appropriate key.'
                }, 400)


    def check_permissions(user, action, resource):
        tenant_name = "casting-agency"
        permitted = permit.check(user, action, {"type": resource, "tenant": tenant_name})
        if not permitted:
            raise AuthError({
                'code': 'unauthorized',
                'description': 'Permission not found.'
            }, 403)

        return True




    def requires_auth(action, resource):
        def requires_auth_decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                # get access_token from user session

                token = session['user']['id_token']
                if not token:
                    raise AuthError({
                        'code': 'invalid_header',
                        'description': 'Authorization not found.'
                    }, 401)
                
                payload = verify_decode_jwt(token)
                user = payload['email']               
                check_permissions(user, action, resource)

                return f(*args, **kwargs)

            return wrapper
        return requires_auth_decorator


    @app.route("/login")
    def login():
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True)
        )

    @app.route("/callback", methods=["GET", "POST"])
    def callback():
        token = oauth.auth0.authorize_access_token()
        session["user"] = token

        permit_user = {
            # add the key attribute from auth0 -> token -> userinfo -> sid to pemit
            "key": token["userinfo"]["sid"],
            "email": token["userinfo"]["email"]
        }
        permit.api.sync_user(permit_user)
        

        return redirect("/")

    @app.route("/")
    def home():
        return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))




    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(
            "https://" + os.getenv("AUTH0_DOMAIN")
            + "/v2/logout?"
            + urlencode(
                {
                    "returnTo": url_for("home", _external=True),
                    "client_id": os.getenv("AUTH0_CLIENT_ID"),
                },
                quote_via=quote_plus,
            )
        )

    
    from . import models


    @app.route('/actors', methods=['GET'], endpoint='get_actors')
    @requires_auth('read', 'actors')
    def read_all_actors():

        # using the try-except method to create the query
        try:
            #models.db_drop_and_create_all()

            # create the query actors order by id
            query_actors = models.Actors.query.all()

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

    # from . import routes
    # app.register_blueprint(routes.bp)

    #Error Handling

    @app.errorhandler(422)
    def unprocessable(error):
        return jsonify({
            "success": False,
            "error": 422,
            "message": "unprocessable"
        }), 422



    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": 404,
            "message": "resource not found"
        }), 404


    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "success": False,
            "error": 401,
            "message": "unauthorized"
        }), 401


    # error handler for Auth
    @app.errorhandler(AuthError)
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response


    # error handler for 400
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "success": False,
            "error": 400,
            "message": "bad request"
        }), 400


    # error handler for 405
    @app.errorhandler(405)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": 405,
            "message": "method not allowed"
        }), 405


    # error handler for 500
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "success": False,
            "error": 500,
            "message": "internal server error"
        }), 500


    return app