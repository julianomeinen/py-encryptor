FROM python:3.6
COPY ./app/ /app
WORKDIR /app
COPY ../requirements.txt requirements.txt
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]