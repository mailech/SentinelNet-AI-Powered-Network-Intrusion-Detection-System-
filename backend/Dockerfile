# Use official Python image
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy root-level requirements first helper
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY . .

# Training must happen or artifacts must be copied
# CMD ["python", "train_model.py"]

# Command to run for API
CMD ["uvicorn", "main.py:app", "--host", "0.0.0.0", "--port", "8000"]
