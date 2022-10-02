import os
import json
import unittest
from flask_sqlalchemy import SQLAlchemy
from casting import create_app
from casting.models import db_drop_and_create_all, Movies, Actors
from sqlalchemy.orm.session import close_all_sessions


from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.



# This class represents the App test case
class AppTestCase(unittest.TestCase):

    def setUp(self):
        # Define test variables and initialize app.
        self.app = create_app()
        self.client = self.app.test_client

        # Binds the app to the current context
        with self.app.app_context():
            self.db = SQLAlchemy()
            self.db.init_app(self.app)

            # drop all tables and create new ones
            db_drop_and_create_all()

        self.new_title = 'Planet of the Apes'
        self.new_release_date = 1968

        self.new_movie = {
            "title": "Planet of the Apes",
            "release_date": 1968
        }

        self.update_title = 'Escape from the Planet of the Apes'
        self.update_release_date = 1971

        self.update_movie = {
            "title": "Escape from the Planet of the Apes",
            "release_date": 1971
        }

        self.new_name = 'Charlton Heston'
        self.new_age = 84
        self.new_gender = 'Male'

        self.new_actor = {
            "name": "Charlton Heston",
            "age": 84,
            "gender": "Male"
        }

        self.update_name = 'Roddy McDowall'
        self.update_age = 70
        self.update_gender = 'Male'

        self.update_actor = {
            "name": "Roddy McDowall",
            "age": 70,
            "gender": "Male"
        }

    def tearDown(self):

        # Executed after reach test
        close_all_sessions()
        pass

    def test_create_movie_rbac_permission_not_found(self):

        #Load jwt from environment variables
        jwt = os.getenv("ASSITENT_JWT")

        # Define movies route
        res = self.client().post("/movies", json=self.new_movie, headers={"Authorization": f"Bearer {jwt}"})
        
        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return Permission not found
        self.assertEqual(res.status_code, 403)
        self.assertEqual(data["code"], "unauthorized")
        self.assertEqual(data["description"], "Permission not found.")
    

    def test_create_movie(self):

        #Load jwt from environment variables
        jwt = os.getenv("PRODUCER_JWT")

        # Define movies route
        res = self.client().post("/movies", json=self.new_movie, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertEqual(data["movies"][0]["title"], self.new_title)
        self.assertEqual(data["movies"][0]["release_date"], self.new_release_date)

        # Check return data
        self.assertTrue(len(data["movies"]))
    
    
    def test_create_movie_bad_request(self):

        #Load jwt from environment variables
        jwt = os.getenv("PRODUCER_JWT")

        # Set an empty movie to test
        self.new_movie = {}

        # Define movies route with wrong URL
        res = self.client().post("/movies", json=self.new_movie, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 400)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "bad request")
    

    def test_read_all_movies(self):

        #Load jwt from environment variables
        jwt = os.getenv("ASSITENT_JWT")

        # Define movies route
        res = self.client().get("/movies", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertTrue(len(data["movies"]))

            # Check return data
        self.assertTrue(len(data["movies"]))
    
    def test_read_all_movies_method_not_allowed(self):
        
        #Load jwt from environment variables
        jwt = os.getenv("ASSITENT_JWT")

        # Define movies route
        res = self.client().get("/movies/2", headers={"Authorization": f"Bearer {jwt}"})
       
        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 405)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "method not allowed")
        

    def test_update_movie(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Define movies route
        res = self.client().patch("/movies/1", json=self.update_movie, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertEqual(data["movies"][0]["title"], self.update_title)
        self.assertEqual(data["movies"][0]["release_date"], self.update_release_date)
        
    def test_update_movie_unprocessable(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Define movies route
        res = self.client().patch("/movies/2", json=self.update_movie, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 422)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "unprocessable")
        
    def test_delete_movie_rbac_permission_not_found(self):
        
        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Define movies route
        res = self.client().delete("/movies/1", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 403)
        self.assertEqual(data["code"], "unauthorized")
        self.assertEqual(data["description"], "Permission not found.")


    def test_delete_movie(self):

        #Load jwt from environment variables
        jwt = os.getenv("PRODUCER_JWT")

        # Define movies route
        res = self.client().delete("/movies/1", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertEqual(data["delete"], 1)

       

    def test_delete_movie_resource_not_found(self):

        #Load jwt from environment variables
        jwt = os.getenv("PRODUCER_JWT")

        # Define movies route
        res = self.client().delete("/movies/10", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 404)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "resource not found")
        

# Teste Actors

    def test_create_actor(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Define actors route
        res = self.client().post("/actors", json=self.new_actor, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertEqual(data["actors"][0]["name"], self.new_name)
        self.assertEqual(data["actors"][0]["age"], self.new_age)
        self.assertEqual(data["actors"][0]["gender"], self.new_gender)

        # Check return data
        self.assertTrue(len(data["actors"]))
        

    def test_create_actor_bad_request(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Set an empty actor to test
        self.new_actor = {}

        # Define actors route with wrong URL
        res = self.client().post("/actors", json=self.new_actor, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 400)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "bad request")
    

    def test_read_all_actors(self):

        #Load jwt from environment variables
        jwt = os.getenv("ASSITENT_JWT")

        # Define actors route
        res = self.client().get("/actors", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)

        # Check return data
        self.assertTrue(len(data["actors"]))
    

    def test_read_all_actors_method_not_allowed(self):

        #Load jwt from environment variables
        jwt = os.getenv("ASSITENT_JWT")

        # Define actors route
        res = self.client().get("/actors/2", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 405)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "method not allowed")


    def test_update_actor(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Define actors route
        res = self.client().patch("/actors/1", json=self.update_actor, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertEqual(data["actors"][0]["name"], self.update_name)
        self.assertEqual(data["actors"][0]["age"], self.update_age)
        self.assertEqual(data["actors"][0]["gender"], self.update_gender)
    

    def test_update_actor_unprocessable(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")
        
        # Define actors route
        res = self.client().patch("/actors/2", json=self.update_actor, headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 422)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "unprocessable")
        
    def test_delete_actor(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")
    
        # Define actors route
        res = self.client().delete("/actors/1", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data["success"], True)
        self.assertEqual(data["delete"], 1)

    
    def test_delete_actor_resource_not_found(self):

        #Load jwt from environment variables
        jwt = os.getenv("DIRECTOR_JWT")

        # Define actors route
        res = self.client().delete("/actors/10", headers={"Authorization": f"Bearer {jwt}"})

        # create the data dictionary from the URL request
        data = json.loads(res.data)

        # Check request return
        self.assertEqual(res.status_code, 404)
        self.assertEqual(data["success"], False)
        self.assertEqual(data["message"], "resource not found")
        

# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()

