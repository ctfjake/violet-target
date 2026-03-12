FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Data volume mount point for the SQLite database
RUN mkdir -p /data

ENV DATABASE_PATH=/data/chirpy.db
ENV FLASK_APP=app.py

EXPOSE 5000

CMD ["python", "app.py"]
