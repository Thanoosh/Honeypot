# services/http/Dockerfile

FROM python:3.10-slim

WORKDIR /app

COPY app.py .

RUN pip install flask requests

EXPOSE 8080

CMD ["python", "app.py"]
