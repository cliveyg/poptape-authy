FROM python:3.12-slim

# this needs to match the directory/package name of the python app
COPY . /authy
WORKDIR /authy

# remove unwanted files and folders
RUN rm -rf vauthy
RUN rm -rf migrations
RUN rm -rf app/tests
RUN mkdir -p /authy/log

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 8001 available to the world outside this container
EXPOSE 8001

# Define environment variables here
# args are passed it from cli or docker-compose.yml
ARG poptape_auth_user
ARG poptape_auth_pass
ENV NAME cliveyg
ENV POPTAPE_AUTH_USER {$poptape_auth_user}
ENV POPTAPE_AUTH_PASS {$poptape_auth_pass}

# if -u flag in CMD below doesn't work 
# then uncomment this to see python
# print statements in docker logs
ENV PYTHONUNBUFFERED=0

# Run gunicorn when the container launches
CMD ["gunicorn", "-b", "0.0.0.0:8001", "authy:app"]
