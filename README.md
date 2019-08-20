# poptape-auth

A Flask Python based microservice to authenticate and authorize. Uses Postgres as the database. This is a Json based REST API that provides authentication and authorization via JWT. All endpoints that require authorization to use must have a JWT token in the HTTP header 'x-access-token'. I'm probably going to change this for production as the microservices will sit behind an API server and the system will use public/private keys for encoding the JWT and won't need to call authorization on every call. This will reduce network traffic a lot.

This is a heavily refactored version of my earlier login microservice. It has been changed to a application factory to enable easier unit tesing amongst other advantages.

Please see [this gist](https://gist.github.com/cliveyg/cf77c295e18156ba74cda46949231d69) to see how this microservcie works as part of the auction system software.

### API routes

```
/authy [GET] (Unauthenticated)
```
Returns a list of endpoints and accepted methods for each..

Example Output:
```
{
  "endpoints": [
    {
      "methods": ["OPTIONS","HEAD","GET"],
      "url": "/authy/ratelimited"
    },
    {
      "methods": ["OPTIONS","POST"],
      "url": "/authy/login"
    },
    {
      "methods": ["OPTIONS","HEAD","GET"],
      "url": "/authy/role/<role_name>/users"
    },
    .
    .
    .
  ]
}
```
---
```
/authy/login [POST] (Unauthenticated)
```
Returns a JWT token if authentication is successful. Uses an http POST auth 
as HTTP Basic Authorization has problems with utf8 characters in password and 
name fields.

Example Input:
```
{
  "username": "someuser",
  "password": "somepass",
}
```
Example Output:
```
{
  "token": "dkk3FJpM9mnmEO0UHV-CPHAs6aIv5WPTa.dkk3FJpM9mnmEO0UHV-CPHAs6aIv5WPTa.dkk3FJpM9mnmEO0UHV-CPHAs6aIv5WPTadkk3FJpM9mnmEO0UHV-CPHAs6aIv5WPTa",
}
```
---

```
/authy/user [GET] (Authenticated)
```
Returns a the currently logged in users' details.


Example Output:
```
{
  "created": "Tue, 11 Jun 2019 10:03:09 GMT",
  "email": "joe@email.com",
  "last_login": "Tue, 20 Aug 2019 09:13:43 GMT",
  "public_id": "f38ba39a-3682-4803-a498-659f1cd8a304",
  "username": "joeb"
}
```
---

#### Notes:
* Creating a user currently fails the AWS part as the AWS microservice isn't 
finished and dockerized. When the dev version of poptape-aws is running a user
is created without errors. As is, the user is created in the auth DB but the 
authy microservice still returns a 500 - as it's coded to do. Maybe change the 
return code to something else rather than 500?

#### Tests:
Tests can be run from app root (/path/to/authy) using: `pytest --cov-config=app/tests/.coveragerc --cov=app app/tests`
Current test coverage is around 96%

#### Docker:
This app can now be run in Docker using the included docker-compose.yml and Dockerfile. The database and roles still need to be created manually after successful deployment of the app in Docker. It's on the TODO list to automate these parts :-)

#### TODO:
* Complete this documentation!
* ~~Add call to AWS microservice to create AWS user details.~~
* Make test coverage more comprehensive.
* Refactor tests to mock AWS microservice call.
* Add auditing with calls to Rabbit MQ
* Make code pep8 compliant even though imo pep8 code is uglier and harder to read ;-)
* Automate docker database creation and population.

