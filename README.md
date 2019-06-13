# poptape-auth

A Flask Python based microservice to authenticate and authorize. Uses Postgres as the database. This is a Json based REST API that provides authentication and authorization via JWT. All endpoints that require authorization to use must have a JWT token in the HTTP header 'x-access-token'

This is a heavily refactored version of my earlier login microservice. It has been changed to a application factory to enable easier unit tesing amongst other advantages.

### API routes

```
/authy [GET] (Unauthenticated)

Returns a list of endpoints and accepted methods for each..
Valid return codes: [200]

Example Output:
{
  "endpoints": [
    {
      "methods": ["OPTIONS","HEAD","GET"],
      "url": "/authy/ratelimited"
    }
  ]
}

-------------------------------------------------------------------------------

/authy/login [POST] (Unauthenticated)

Returns a JWT token if authentication is successful. I am using for based auth 
as HTTP Basic Authorization has problems with utf8 characters in password and 
name fields.
Valid return codes: [200, 400, 401, 429, 500]

Example Input:
{
  "username": "someuser",
  "password": "somepass",
}

Example Output:
{
  "token": "biglongstringforjwt",
}

-------------------------------------------------------------------------------

```

#### Notes:

#### Tests:
Tests can be run from app root (/path/to/authy) using: `pytest --cov-config=app/tests/.coveragerc --cov=app app/tests`
Current test coverage is around 96%

#### Docker:
This app can now be run in Docker using the included docker-compose.yml and Dockerfile. The database and roles still need to be created manually after successful deployment of the app in Docker. It's on the TODO list to automate these parts :-)

#### TODO:
* Complete this documentation!
* Add call to AWS microservice to create AWS user details.
* Make test coverage more comprehensive.
* Add auditing with calls to Rabbit MQ
* Make code pep8 compliant even though imo pep8 code is uglier and harder to read ;-)
* Automate docker database creation and population.

