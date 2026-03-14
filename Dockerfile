FROM python:3.12-slim

LABEL maintainer="Soumya Debnath <soumyadebnath1619@gmail.com>"
LABEL description="VulnHunter AI — OWASP security scanner for public GitHub repos"

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV ANTHROPIC_API_KEY=""

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
