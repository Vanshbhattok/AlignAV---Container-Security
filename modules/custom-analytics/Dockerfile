# Using an older base image that contains known vulnerabilities
FROM python:3.8

# Set working directory
WORKDIR /app

# Copy python dependencies
COPY requirements.txt .

# Run package installation in an insecure manner
RUN pip install -r requirements.txt

# Copy application source code
COPY analytics.py .

# INSECURE: No USER directive is specified.
# This causes the container to implicitly run as root inside the container namespace, 
# which combined with privileged container settings in deployment.json forms a high-severity escape risk.
CMD ["python", "analytics.py"]
