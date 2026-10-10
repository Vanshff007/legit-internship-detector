# One image: builds the web app, then runs the API, which also serves the web app.
# The text model is copied from ml/artifacts/ (git-ignored). Build it with ml/train_baseline.py,
# or download it: gh release download model-text-baseline-v1 --pattern "*.joblib" --dir ml/artifacts

FROM node:22-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

# Hosting platforms such as Hugging Face Spaces run the container as uid 1000.
RUN useradd --create-home --uid 1000 app
WORKDIR /app/backend

COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install .

COPY ml/artifacts/text-baseline-v1.joblib /app/ml/artifacts/text-baseline-v1.joblib
COPY --from=web /web/dist /app/web/dist

# Feedback database lives here; mount a volume to keep it across restarts.
RUN mkdir -p /app/backend/data && chown -R app:app /app/backend/data
USER app

EXPOSE 8000
# --proxy-headers so rate limits see the real client address behind the platform's proxy.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips=*"]
