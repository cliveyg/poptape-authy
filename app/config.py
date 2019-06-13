# app/config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config(object):
    # set app configs
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_FILENAME = os.getenv('LOG_FILENAME')
    LOG_LEVEL = os.getenv('LOG_LEVEL')
    BASE_URLS = os.getenv('BASE_URLS')
    ENVIRONMENT = os.getenv('ENVIRONMENT')
    USERS_LIMIT_PER_PAGE = os.getenv('USERS_LIMIT_PER_PAGE')
    AWS_URL = os.getenv('AWS_URL')

class TestConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_TESTDB_URI')
    LOG_LEVEL = "DEBUG"
    ENVIRONMENT = "TEST"
    USERS_LIMIT_PER_PAGE = "3"
    BASE_URLS = os.getenv('TEST_BASE_URLS')
