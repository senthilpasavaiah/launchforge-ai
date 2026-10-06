FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10001 --create-home outreach && mkdir /data && chown outreach:outreach /data
USER outreach
ENV OUTREACH_DB=/data/outreach.sqlite
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "2", "--timeout", "60", "outreach.app:application"]
