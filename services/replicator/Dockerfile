FROM python:3.14-alpine

WORKDIR /app

COPY ./requirements.txt /app/
RUN pip install -r ./requirements.txt

COPY . /app

STOPSIGNAL SIGINT

CMD ["python", "app.py"]
