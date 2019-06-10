# app/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_uuid import FlaskUUID
from flask_limiter.util import get_remote_address

# -----------------------------------------------------------------------------
# set up SQL alchemy
db = SQLAlchemy()

# -----------------------------------------------------------------------------
# set up rate limiting
limiter = Limiter(key_func=get_remote_address,
                  default_limits=["50 per minute", "5 per second"])

# -----------------------------------------------------------------------------
# set up flask uuid regex in url finder
flask_uuid = FlaskUUID()

