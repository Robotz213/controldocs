FROM python:3

COPY . /app
WORKDIR /app

RUN pip install hashlib mysql-connector-python flask flask-mysqldb passlib flask_mail Werkzeug
CMD python app.py

