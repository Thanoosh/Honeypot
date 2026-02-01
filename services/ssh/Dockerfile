# services/ssh/Dockerfile

FROM python:3.10-slim

WORKDIR /app

COPY ssh_honeypot.py .

RUN pip install paramiko requests

EXPOSE 2222

CMD ["python", "ssh_honeypot.py"]
