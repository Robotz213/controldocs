FROM python:3

COPY . /app
WORKDIR /app

RUN pip install flask flask-mysqldb passlib flask_mail
CMD python app.py

