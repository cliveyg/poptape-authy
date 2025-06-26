FROM python:3.12-slim

# this needs to match the directory/package name of the python app
COPY . /authy
WORKDIR /authy

# remove unwanted files and folders
RUN rm -rf vauthy && \
    rm -rf migrations && \
    rm -rf app/tests && \
    mkdir -p /authy/log \

RUN apt-get clean && apt-get update && apt-get install -y curl

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 8001 available to the world outside this container
EXPOSE $PORT

# if -u flag in CMD below doesn't work 
# then uncomment this to see python
# print statements in docker logs
ENV PYTHONUNBUFFERED=0

# Run gunicorn when the container launches
# we can't pass in the port env to docker CMD :(
CMD ["gunicorn", "-b", "0.0.0.0:8001", "authy:app"]
