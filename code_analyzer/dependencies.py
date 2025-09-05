import re
from pathlib import Path

def parse_requirements_txt(file_path):
    """
    Парсит requirements.txt и возвращает {библиотека: версия}
    """
    deps = {}
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([a-zA-Z0-9_\-\.]+)([=><!~]+)([\w\.\*]+)?", line)
            if m:
                name, _, version = m.groups()
                deps[name.lower()] = version or ""
            else:
                deps[line.lower()] = ""
    return deps

def parse_package_json(file_path):
    """
    Парсит package.json (nodejs) и возвращает {библиотека: версия}
    """
    import json
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
        deps = {}
        for section in ["dependencies", "devDependencies"]:
            for pkg, version in data.get(section, {}).items():
                deps[pkg.lower()] = version
    return deps

def find_dependency_files(project_path):
    """
    Находит files зависимости (requirements.txt, package.json) в проекте.
    """
    p = Path(project_path)
    result = []
    for fname in ["requirements.txt", "package.json"]:
        f = p / fname
        if f.exists():
            result.append(str(f))
    return result