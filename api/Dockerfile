FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the API code (because the build context IS the api folder)
COPY . .

# Environment + exposed port
ENV PORT=8000
EXPOSE 8000

# Start FastAPI using Uvicorn
CMD ["python", "-m", "uvicorn", "app_boto:app", "--host", "0.0.0.0", "--port", "8000"]
