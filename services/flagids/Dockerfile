FROM python:3.14-alpine

WORKDIR /app

COPY ./ /app/

COPY ./requirements.txt /app/

RUN pip install -r ./requirements.txt

COPY ./flagids.py /app/

STOPSIGNAL SIGINT

CMD ["python3", "./flagids.py"]
