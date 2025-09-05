import ast

import utils
from utils import build_llama_code_prompt, parse_llama_json
import subprocess

class CodeAnalyzer:
    def __init__(self, llama_model="llama3"):
        self.llama_model = llama_model

    def find_vulnerable_calls(self, file_path, function_names):
        """
        Ищет вызовы уязвимых функций в Python-файле.
        Возвращает список найденных совпадений: строка, имя функции, аргументы.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        print(f"File text: {source}")
        tree = ast.parse(source)
        calls = []

        class CallVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                func_name = getattr(node.func, 'id', None)
                if not func_name and isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if func_name in function_names:
                    calls.append({
                        "line": node.lineno,
                        "function": func_name,
                        "args": [ast.unparse(arg) if hasattr(ast, "unparse") else "" for arg in node.args]
                    })
                self.generic_visit(node)

        CallVisitor().visit(tree)
        return calls

    def ai_code_analysis(self, file_content, vuln_funcs_summary):
        """
        Использует Ollama LLM для дополнительно анализа кода на предмет уязвимых паттернов.
        """
        prompt = build_llama_code_prompt(file_content, vuln_funcs_summary)
        output = utils.query_ollama(prompt, "llama3")
        return parse_llama_json(output)

