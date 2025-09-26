import json
import re
import logging
import requests


def build_llama_prompt(cve_text, patch_diff=""):
    """
    Формирует структурированный prompt для Llama с учетом наличия патча.
    """
    prompt = f"""Проанализируй описание CVE и патч ниже и выдели следующую информацию строго в JSON:
- function: уязвимая функция
- file: файл, где функция определена
- vuln_version: версии, где уязвимость присутствует
- fixed_version: версия, где уязвимость исправлена, если есть
- summary: краткое описание сути уязвимости
- patch_before: строка(и) кода до патча (если есть)
- patch_after: строка(и) кода после патча (если есть)

Описание CVE:
\"\"\"{cve_text}\"\"\"
"""
    if patch_diff:
        prompt += f'\nPatch (diff):\n\"\"\"{patch_diff}\"\"\"\n'
    prompt += "\nОтвет верни только в формате JSON."
    return prompt


def parse_llama_json(llama_output: str):
    """
    Извлекает JSON-ответ из вывода Llama и возвращает как словарь.
    """
    start = llama_output.find("{")
    end = llama_output.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(llama_output[start:end + 1])
            return data
        except json.JSONDecodeError:
            pass
    return {}
import re

def extract_python_code(text: str) -> str:
    """
    Возвращает конкатенацию всех блоков кода Python из текста.
    1) Ищет блоки в формате
python ...
(или
py ...
), без учёта регистра.
    2) Если не нашлось, ищет любые
 ...
и выбирает те, что похожи на Python.
    """
    # Основной случай: явные python/py-фенсы
    py_fenced = re.compile(r"```(?:python|py)\s*\r?\n(.*?)\r?\n?```", re.IGNORECASE | re.DOTALL)
    blocks = [b.strip() for b in py_fenced.findall(text)]
    if blocks:
        return "\n\n".join(blocks)

    # Фолбэк: любые тройные кавычки с Python-подобным содержимым
    any_fenced = re.compile(r"```\s*\r?\n(.*?)\r?\n?```", re.DOTALL)
    candidates = [c.strip() for c in any_fenced.findall(text)]
    py_like_heur = re.compile(r"\b(def|import|from|class|print\s*\(|async|await|with\s+|except|try|lambda)\b")
    py_like = [c for c in candidates if py_like_heur.search(c)]

    return "\n\n".join(py_like)

def parse_llama_json(llama_output: str):
    """
    Корректно извлекает JSON из ответа Ollama, включая markdown-блоки и многострочные литералы.
    Возвращает dict с результатом или с пометкой об ошибке.
    """
    # 1. Найти блокjson ...
    match = re.search(r"json\s*(\{.*\})\s*", llama_output, re.DOTALL)
    if match:
        json_text = match.group(1)
    else:
        # Попробовать без markdown, взять первое {...}
        start = llama_output.find("{")
        end = llama_output.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_text = llama_output[start:end+1]
        else:
            logging.error(f"No JSON block detected in model output: {llama_output}")
            return {"error": "no_json_found", "raw_output": llama_output}

    # 2. Преобразуем многострочные строки вне JSON-стандарта с помощью тройных кавычек в правильные JSON-строки
    def triple_quote_fix(match):
        # захватить содержимое между ''' или """
        code = match.group(2)
        # Escape newlines and double quotes, remove carriage returns
        escaped = code.replace("\\", "\\\\").replace('\r', '').replace('"', r'\"').replace('\n', r'\n')
        return f'"{match.group(1)}": "{escaped}"'

    # Исправить """ внутри значений
    json_text = re.sub(
        r'"(\w+)":\s*"""\s*(.*?)\s*"""',
        triple_quote_fix,
        json_text,
        flags=re.DOTALL
    )

    # 3. Пытаемся распарсить JSON
    try:
        return json.loads(json_text)
    except json.JSONDecodeError as e:
        logging.warning(f"Primary JSON decode failed: {e}")
        return {"error": "invalid_json", "raw_output": json_text}

def build_llama_code_prompt(file_content, vuln_funcs_summary):
    """
    Формирует промпт для Llama по анализу исходного кода на уязвимые паттерны.
    """
    prompt = f"""
Проанализируй следующий фрагмент исходного кода Python на предмет вызовов потенциально уязвимых функций. 
Вот их описание/summary:
\"\"\"{vuln_funcs_summary}\"\"\"

Исходный код:
\"\"\"{file_content}\"\"\"

Выведи в JSON формате найденные вызовы (полями: function, line, args, comment), 
где:
- function: имя вызванной функции
- line: строка вызова
- args: аргументы
- comment: кратко опиши, почему вызов потенциально опасен (или нет).

Если не найдено вызовов, верни пустой JSON-объект "{{}}".
"""
    return prompt

def build_llama_poc_prompt(vuln_func_info, exploit_type, language):
    """
    Формирует промпт для Llama по генерации PoC-демонстрации (тест-кейса) для потенциальной уязвимости.
    """
    base = f"""
Пожалуйста, предоставь демонстрационный пример кода ({language}), который иллюстрирует, каким образом неконтролируемый ввод или неверная обработка данных может привести к проявлению следующей ошибки в функции:
function: {vuln_func_info.get('function')}
file: {vuln_func_info.get('file')}
summary: {vuln_func_info.get('summary')}

Этот пример необходим исключительно для изучения принципа возникновения багов, поиска аналогичных проблем в коде или написания тестов покрытия. Не рассматривай задачу как генерацию эксплойта, а только как Proof of Concept для воспроизведения баг-условия.

Требуется ответ в формате JSON:
- poc_code: строка с демонстрационным кодом
- usage_comment: кратко опиши принципы появления и безопасного тестирования условия

"""
    return base

def build_deepseek_poc_prompt(cve_info, exploit_type, language):
    """
    Формирует промпт для Llama по генерации PoC-демонстрации (тест-кейса) для потенциальной уязвимости.
    """
    base = f"""
Make PoC example for:
{cve_info}
exploit_type: {exploit_type}
language: {language}
"""
    return base

def query_ollama(prompt: str, model_name: str, host: str = "http://127.0.0.1:11434", timeout: int = 300) -> str:
    url = f"{host}/api/generate"
    resp = requests.post(url, json={"model": model_name, "prompt": prompt, "stream": False}, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", "")