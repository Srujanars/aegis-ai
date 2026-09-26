FROM python:3.11-slim

WORKDIR /app

COPY . /app

EXPOSE 5050

CMD ["python3", "backend/server.py"]
