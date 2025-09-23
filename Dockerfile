FROM ollama/ollama:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv curl ca-certificates bash tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Создаем виртуальную среду
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Обновляем pip внутри venv
RUN pip install --no-cache-dir --upgrade pip

# Устанавливаем зависимости проекта
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Копируем исходники
COPY . /app

# Переменная каталога моделей (по умолчанию /root/.ollama)
ENV OLLAMA_MODELS=/root/.ollama

# Предзагрузка модели в образ:
# - запускаем ollama serve в фоне
# - ждём готовности API
# - тянем модель
# - останавливаем демон
RUN (ollama serve & pid=$!; \
    until curl -sf http://127.0.0.1:11434/api/tags >/dev/null; do sleep 0.5; done; \
    ollama pull deepseek-coder:latest; \
    kill $pid; wait $pid || true)

# Скрипт запуска, поднимет ollama serve и ваше приложение
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Порты: 11434 — Ollama, 5000 — ваше приложение (Flask)
EXPOSE 11434 5000

# Tini как init-процесс
ENTRYPOINT ["/usr/bin/tini","-g","--"]
CMD ["/entrypoint.sh"]