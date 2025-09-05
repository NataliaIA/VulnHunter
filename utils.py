import json
import re
import logging
import subprocess


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

def query_ollama( prompt: str, model_name: str) -> str:
    process = subprocess.Popen(
        ["ollama", "run", model_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = process.communicate(prompt)
    if process.returncode != 0:
        print("Ошибка:", stderr)
        return ""
    return stdout