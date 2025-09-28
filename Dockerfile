FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OLLAMA_HOST=http://ollama:11434

WORKDIR /app

# Системные зависимости по минимуму
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates bash tini \
 && rm -rf /var/lib/apt/lists/*

# Виртуальная среда (опционально, можно убрать и ставить в системный Python)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Установка зависимостей
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Копируем исходники
COPY . /app

# Приложение слушает 0.0.0.0:5000
EXPOSE 5000

# Запуск только сервиса (обновите команду под ваш фреймворк/entrypoint)
# Пример для Flask:
ENTRYPOINT ["/usr/bin/tini","-g","--"]
CMD ["python","-m","flask","run","--host=0.0.0.0","--port=5000"]