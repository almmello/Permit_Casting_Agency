# Casting Agency

## Motivation for the project
Udacity has decided to open a new digitally enabled Casting Agency for Producers and Directors to manage Actors and Movies.

I recorded my development through commits so that you can follow along.

Please let me know if you find any issues with this project.


## References

During the development, I used the following references to build the Casting Agency app:

- https://learn.udacity.com/nanodegrees/nd0044/
- https://flask-wtf.readthedocs.io/en/1.0.x/
- https://www.digitalocean.com/community/tutorials/how-to-use-flask-sqlalchemy-to-interact-with-databases-in-a-flask-application
- https://www.linkedin.com/learning/full-stack-web-development-with-flask/
- https://flask.palletsprojects.com/en/2.1.x/testing/
- https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xvi-debugging-testing-and-profiling-legacy
- https://testdriven.io/blog/flask-pytest/
- https://www.geeksforgeeks.org/read-json-file-using-python/
- https://flask.palletsprojects.com/en/1.1.x/errorhandling/#generic-exception-handlers
- https://devcenter.heroku.com/articles/flask-memcache
- https://devcenter.heroku.com/articles/getting-started-with-python

## URL location for the hosted API
https://almmello-casting.herokuapp.com/	  
 
# Installing Dependencies

## Python 3.9.14

Follow instructions to install the latest version of Python for your platform in the [python docs](https://docs.python.org/3/using/unix.html#getting-and-installing-the-latest-version-of-python)

## Virtual Environment

We recommend working within a virtual environment whenever using Python for projects. This procedure keeps your dependencies for each project separate and organized. You can find instructions for setting up a virtual environment for your platform in the [python docs](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/)

## Environment Variables:
You need to create a ".env" file in the root directory with the following variables:
- FLASK_APP=casting	 
- FLASK_ENV=development	 
- AUTH0_DOMAIN_NAME=almmello-casting-agency.us.auth0.com	 
- AUTH0_CLIENT_ID=cagency	 
- ASSITENT_JWT=\<supplied in a separate file for security reasons\>	 
- DIRECTOR_JWT=\<supplied in a separate file for security reasons\>	 
- PRODUCER_JWT=\<supplied in a separate file for security reasons\>	 
  

## PIP Dependencies

Once you have your virtual environment setup and running, install dependencies by navigating to the home directory and running:

```bash
pip3 install -r requirements.txt
```

This command will install all the required packages we selected within the `requirements.txt` file.

## Key Dependencies

- [Flask](http://flask.pocoo.org/) is a lightweight backend microservices framework. Flask is required to handle requests and responses.

- [SQLAlchemy](https://www.sqlalchemy.org/) and [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/) are libraries to handle the lightweight SQLite database. 

- [jose](https://python-jose.readthedocs.io/en/latest/) JavaScript Object Signing and Encryption for JWTs. Used for encoding, decoding, and verifying JWTS.

# Auth0 Authentication

1. I created a new Auth0 tenant exclusively for this project.
2. On Ath0,  I created a new single-page application.
3. Then, I created a new API with the following:
Enable RBAC
Enable Add Permissions in the Access Token
4. I created new API permissions:
- get:movies	 
- get:actors	 
- post:actors	 
- delete:actors	 
- patch:actors	 
- patch:movies	 
- post:movies	 
- delete:movies	 
  
6. Created new roles for:
- Assistant: Can view actors and movies
- Director: Can add or delete an actor from the database and modify actors or movies.
- Producer: Can add or delete a movie from the database

7. Finally, I created JWTs for each role and set them for maximum token_lifetime_for_web (86400), so they will expire on September 12th, 2022, 15:49:10 GMT-0300.

## Running the server locally

From within the `./` directory, ensure you work using your created virtual environment.

Each time you open a new terminal session, run:

```bash
flask run
```

# Testing

The test_app.py script uses the Unittest library to test each endpoint success and one error behavior. It also includes tests demonstrating role-based access control.

To deploy the tests, run:
```
python3 test_app.py
```

# Hosting Instructions

We deployed this project on Heroku.
Heroku is a container-based cloud Platform as a Service (PaaS). Developers use Heroku to deploy, manage, and scale modern apps.
I used the Heroku tutorial at:
https://devcenter.heroku.com/articles/flask-memcache


# API Documentation

Find below the detailed documentation of the Casting Agency app API endpoints, including the URL, request parameters, and the response body.

## Base URL

- The address, https://almmello-casting.herokuapp.com, is used to host the app backend.

## Authentication: 
This application uses JWT tokens for authentication.
I'm providing a shell script that will export JWT tokens as environment variables that you can use in combination with the CURL command described below.

## Error Handling

The API returns Errors as JSON objects in the following format:

```
{
    "success": False, 
    "error": 400,
    "message": "bad request"
}
```

The API will return five error types when requests fail:

- 400: Bad Request
- 401: Unauthorized
- 403: Permission Not Found
- 404: Resource Not Found
- 405: Method not Allowed
- 422: Unprocessable
- 500: Internal Server Error


## POST /actors

### Description:

You can create a new actor using the submitted name, age, and gender. The API returns the inserted actor and the success value.

### Sample:

```
curl --location --request POST 'https://almmello-casting.herokuapp.com/actors' \
--header 'Authorization: Bearer <JWT Token>' \
--header 'Content-Type: application/json' \
--data-raw '{"name": "Kim Hunter", "age": 79, "gender": "female"}'
```

### Return:

```
{"actors":[{"age":79,"gender":"female","id":4,"name":"Kim Hunter"}],"success":true}
```

## GET /actors

### Description:

You can retrieve all the actors. The API returns the list of actors and the success value.

### Sample:

```
curl --location --request GET 'https://almmello-casting.herokuapp.com/actors' \
--header 'Authorization: Bearer <JWT Token>'
```

### Return:

```
{"actors":[{"age":79,"gender":"female","id":3,"name":"Kim Hunter"}],"success":true}
```

## PATCH /actors/<id>

### Description:

You can update an existing actor using the submitted name, age, and gender. The API returns the updated actor and the success value.

### Sample:

```
curl --location --request PATCH 'https://almmello-casting.herokuapp.com/actors/4' \
--header 'Authorization: Bearer <JWT Token>' \
--header 'Content-Type: application/json' \
--data-raw '{       
        "name": "Charlton Heston",
        "age": 84,
        "gender": "Male"
}'
```

### Return:
```
{"actors":[{"age":84,"gender":"Male","id":4,"name":"Charlton Heston"}],"success":true}
```

## DELETE /actors/<id>

### Description:

You can delete an actor. The API returns the actor id and the success value.

### Sample:
```
curl --location --request DELETE 'https://almmello-casting.herokuapp.com/actors/3' \
--header 'Authorization: Bearer <JWT Token>' 
```

### Return:
```
{"delete":3,"success":true}
```

## POST /movies

### Description:

You can create a new movie using the submitted title and the release date. The API returns the inserted movie and the success value.

### Sample:

```
curl --location --request POST 'https://almmello-casting.herokuapp.com/movies' \
--header 'Authorization: Bearer <JWT Token>'  \
--header 'Content-Type: application/json' \
--data-raw '{"title": "Beneath the Planet of the Apes", "release_date": 1970}'
```

### Return:

```
{"movies":[{"id":1,"release_date":1970,"title":"Beneath the Planet of the Apes"}],"success":true}
```

## GET /movies

### Description:

You can retrieve all the movies. The API returns the list of movies and the success value.

### Sample:

```
curl --location --request GET 'https://almmello-casting.herokuapp.com/movies' \
--header 'Authorization: Bearer <JWT Token>'
```

### Return:

```
{"movies":[{"id":1,"release_date":1970,"title":"Beneath the Planet of the Apes"}],"success":true}
```

## PATCH /movies/<id>

### Description:

You can update an existing movie using the submitted title and release date. The API returns the updated movie and the success value.

### Sample:

```
curl --location --request PATCH 'https://almmello-casting.herokuapp.com/movies/1' \
--header 'Authorization: Bearer <JWT Token>' \
--header 'Content-Type: application/json' \
--data-raw '{"title": "Escape from the Planet of the Apes", "release_date": 1971}'
```

### Return:
```
{"movies":[{"id":1,"release_date":1971,"title":"Escape from the Planet of the Apes"}],"success":true}
```

## DELETE /movies/<id>

### Description:

You can delete a movie. The API returns the movie id and the success value.

### Sample:
```
curl --location --request DELETE 'https://almmello-casting.herokuapp.com/movies/1' \
--header 'Authorization: Bearer <JWT Token>' 
```

### Return:
```
{"delete":1,"success":true}
```

## Author
-Alexandre Monteiro de Mello

## Acknowledgments
-Udacity Full-Stack Web Development Course

