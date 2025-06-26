FROM python:3.12-slim

# this needs to match the directory/package name of the python app
COPY . /authy
WORKDIR /authy
COPY --chmod=755 run_app.sh /authy

# remove unwanted files and folders
RUN rm -rf vauthy && \
    rm -rf migrations && \
    rm -rf app/tests && \
    mkdir -p /authy/log \

RUN apt-get clean && apt-get update && apt-get install -y curl bash

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

EXPOSE $PORT

# if -u flag in CMD below doesn't work 
# then uncomment this to see python
# print statements in docker logs
ENV PYTHONUNBUFFERED=0

# Run shell script to start gunicorn
CMD ["./run_app.sh"]