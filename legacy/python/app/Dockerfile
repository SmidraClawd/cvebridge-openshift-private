FROM python:3.13.9-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN mkdir /data && chgrp -R 0 /data /app && chmod -R g=u /data /app
COPY app/ /app/app/
USER 10001
EXPOSE 8001
CMD ["python", "-m", "app.server"]
