import utils
from utils import build_llama_prompt, parse_llama_json
import subprocess

class CVEParser:
    def __init__(self, model_name="ollama"):
        self.model_name = model_name

    def parse_cve_and_patch(self, cve_text: str, patch_diff: str = "llama3:latest") -> dict:
        """
        Использует локальную Ollama-модель для парсинга описания CVE и патча.
        Возвращает словарь с интересующими сущностями.
        """
        prompt = build_llama_prompt(cve_text, patch_diff)
        llama_response = utils.query_ollama(prompt, "llama3:latest")
        parsed = parse_llama_json(llama_response)
        return parsed


