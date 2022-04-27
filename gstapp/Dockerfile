FROM python:3.9.6-alpine

WORKDIR /gstapp

ADD . /gstapp
RUN apk add build-base
RUN pip install -r requirements.txt
EXPOSE 8000
ENTRYPOINT ["python"]

CMD ["app.py"]
