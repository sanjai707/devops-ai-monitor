FROM python:3.12-slim

WORKDIR /app/frontend
COPY serve.py ./
COPY dist ./dist

EXPOSE 3000

CMD ["python", "serve.py"]
