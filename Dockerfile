FROM python:3.11-slim

# Create a non-root user (Hugging Face Spaces require this for security)
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

# Set the working directory
WORKDIR /app

# Switch to root temporarily to adjust permissions
USER root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code and give ownership to the 'user'
COPY --chown=user . /app

# Switch back to the non-root user
USER user

# Expose the port (Render handles this dynamically)
EXPOSE 5050

# Run the application with Gunicorn binding to Render's PORT
# using 1 worker to keep the simulation state consistent
CMD gunicorn -b 0.0.0.0:${PORT:-5050} -w 1 --threads 4 app:app
