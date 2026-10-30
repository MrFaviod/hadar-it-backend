FROM python:3.14.8-slim-bookworm@sha256:44e000a07b48bef1517a2b14adc93c17af728ca98858b5e24c6e1b18de1b2ef2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 itsm \
    && useradd --uid 10001 --gid itsm --no-create-home itsm \
    && mkdir -p /data/app /data/tasks /data/attachments /data/dev /data/demo /data/backups /data/backup-status \
    && chmod 0700 /data/backup-status \
    && chown -R itsm:itsm /data
COPY pyproject.toml alembic.ini ./
COPY itsm ./itsm
COPY migrations ./migrations
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "itsm.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
