# app/config.py
import os
from dotenv import load_dotenv
import sys

load_dotenv()

class Config(object):
    # set app configs
    SECRET_KEY = os.getenv('SECRET_KEY') or byebye() 
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI') or byebye()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_FILENAME = os.getenv('LOG_FILENAME') or byebye()
    LOG_LEVEL = os.getenv('LOG_LEVEL') or byebye()
    BASE_URLS = os.getenv('BASE_URLS') or byebye()
    ENVIRONMENT = os.getenv('ENVIRONMENT') or byebye()
    USERS_LIMIT_PER_PAGE = os.getenv('USERS_LIMIT_PER_PAGE') or byebye()
    AWS_URL = os.getenv('AWS_URL') or byebye()
    RESTRICTED_USERNAMES = os.getenv('RESTRICTED_USERNAMES').split(",") or byebye()

class TestConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_TESTDB_URI')
    LOG_LEVEL = "DEBUG"
    ENVIRONMENT = "TEST"
    USERS_LIMIT_PER_PAGE = "3"
    BASE_URLS = os.getenv('TEST_BASE_URLS')

def byebye():
    sys.exit('missing config data from .env file')
