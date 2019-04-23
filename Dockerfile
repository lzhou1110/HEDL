FROM python:3.6

WORKDIR /app
ADD . /app
RUN pip install -r requirements.txt

RUN python setup.py build_ext --inplace

ENTRYPOINT ["python"]
CMD ["app.py"]