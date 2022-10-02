from casting import db


def db_drop_and_create_all():
    # Creates a movie with the given title and release date
    movie = Movies(
        title=' Planet of the Apes',
        release_date=1968
    )

    # Creates an actor with the given name, age and gender
    actor = Actors(
        name = 'Charlton Heston',
        age = 84,
        gender = 'Male'
    )

    # Clear tables and start fresh
    db.drop_all()
    db.create_all()

    # add one demo row
    movie.insert()
    actor.insert()
    

# ROUTES


# Movies with attributes title and release date

class Movies(db.Model):
    # Autoincrementing, unique primary key
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    release_date = db.Column(db.Integer, nullable=False)

    # Create
    def insert(self):
        db.session.add(self)
        db.session.commit()

    # Read
    def read(self):
        return {
            'id': self.id,
            'title': self.title,
            'release_date': self.release_date
        }

    # Update
    def update(self):
        db.session.commit()
    
    # Delete
    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<Movie: {}>'.format(self.title)

# Actors with attributes name, age and gender
class Actors(db.Model):
    # Autoincrementing, unique primary key
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(120), nullable=False)

    # Create
    def insert(self):
        db.session.add(self)
        db.session.commit()
    
    # Read
    def read(self):
        return {
            'id': self.id,
            'name': self.name,
            'age': self.age,
            'gender': self.gender,
        }

    # Update
    def update(self):
        db.session.commit()

   # Delete
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def __repr__(self):
        return '<Actors: {}>'.format(self.name)