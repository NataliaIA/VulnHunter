import logging

import utils
from utils import build_llama_poc_prompt, parse_llama_json
import subprocess

class PoCGenerator:
    def __init__(self, llama_model="llama3"):
        self.llama_model = llama_model

    def generate_poc(self, vuln_func_info, exploit_type="RCE", language="python"):
        """
        Генерирует PoC-эксплойт при помощи Ollama LLM.
        vuln_func_info: dict с полями function, file, summary и т.д.
        exploit_type: тип атаки (например, "RCE", "XSS", "SQLi")
        language: язык целевого PoC
        Возвращает dict с PoC-кодом и кратким описанием.
        """
        prompt = build_llama_poc_prompt(vuln_func_info, exploit_type, language)
        response = utils.query_ollama(prompt, "llama3")
        print(f"Poc model output: {response}")
        return parse_llama_json(response)

