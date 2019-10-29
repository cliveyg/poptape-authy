# app/models.py
from app import db
import datetime

#-----------------------------------------------------------------------------#
# models match to tables in mysql db
#-----------------------------------------------------------------------------#

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True)
    created = db.Column(db.TIMESTAMP(), nullable=False, default=datetime.datetime.utcnow)
    last_login = db.Column(db.TIMESTAMP(), nullable=True)
    validated = db.Column(db.Boolean, default=False)
    validation_string = db.Column(db.VARCHAR(160))
    password_reset_string = db.Column(db.VARCHAR(160))
    password_reset_datetime = db.Column(db.TIMESTAMP(), nullable=True)
    deleted = db.Column(db.Boolean, default=False)
    delete_date = db.Column(db.TIMESTAMP(), nullable=True)

    def __repr__(self): # pragma: no cover 
        return '<id User {}>'.format(self.id)

class Role(db.Model):

    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(100))
    level = db.Column(db.Integer, unique=True)

class UserRole(db.Model):

    __tablename__ = 'user_role'

    user_id = db.Column(db.Integer, db.ForeignKey(User.id), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey(Role.id), primary_key=True)

    
