#!/usr/bin/env bash
set -euo pipefail

# Запуск Ollama в фоне
ollama serve &
OLLAMA_PID=$!

# Ждём готовности API
until curl -sf http://127.0.0.1:11434/api/tags >/dev/null; do
  echo "Waiting for Ollama..."
  sleep 0.5
done

# Убедимся, что модель есть (на всякий случай)
if ! ollama list | grep -q "^deepseek-coder\s\+latest"; then
  echo "Model deepseek-coder:latest not found, pulling..."
  ollama pull deepseek-coder:latest
fi

# Запуск вашего приложения
# Если у вас Flask, можно использовать flask run, но тут — просто app.py
# При необходимости измените команду запуска ниже
exec python -m flask run --host=0.0.0.0 --port=5000