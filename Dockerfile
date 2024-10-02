# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements.txt file into the container
COPY requirements.txt requirements.txt

# Install the dependencies specified in the requirements.txt file
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Set environment variables for Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5005

# Expose the port that the app runs on
EXPOSE 5005

# Add healthcheck
HEALTHCHECK CMD curl --fail http://localhost:5005/ || exit 1

# Command to run the application
CMD ["flask", "run", "--host=0.0.0.0", "--port=5005"]