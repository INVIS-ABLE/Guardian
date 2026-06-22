# Guardian dashboard image.
FROM python:3.11-slim

WORKDIR /app

# Install only what the dashboard/core needs (security tools live in CI/their own images).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
# Run as non-root.
RUN useradd --create-home guardian && chown -R guardian:guardian /app
USER guardian

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
