# Use a lightweight python runtime
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy the server script and the deployment manifest
COPY mock_iot_hub.py deployment.json ./

# Expose the dashboard port
EXPOSE 8080

# Run the dashboard with unbuffered output so logs print immediately in CI
CMD ["python", "-u", "mock_iot_hub.py"]
