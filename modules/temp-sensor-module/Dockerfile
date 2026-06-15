# Use a lightweight, specific python version to limit vulnerabilities
FROM python:3.11-slim

# Create a non-privileged system user and group
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -s /sbin/nologin appuser

# Set working directory
WORKDIR /app

# Copy python dependencies
COPY requirements.txt .

# Install dependencies in a secure manner
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY temp_sensor.py .

# Ensure app directory permissions are restricted
RUN chown -R appuser:appuser /app

# Switch to the non-privileged user context
USER appuser:appuser

# Command to run
CMD ["python", "-u", "temp_sensor.py"]
