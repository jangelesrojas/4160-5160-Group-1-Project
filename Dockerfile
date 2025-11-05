FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY ./api /app

ENV PORT=8000
EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app_boto:app", "--host", "0.0.0.0", "--port", "8000"]
