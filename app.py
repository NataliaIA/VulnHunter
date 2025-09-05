from flask import Flask, request
from flask_restx import Api, Resource, fields
from cve_parser.parser import CVEParser
from code_analyzer.analyzer import CodeAnalyzer
from code_analyzer.dependencies import parse_requirements_txt, find_dependency_files
from poc_generator.generator import PoCGenerator
import os

app = Flask(__name__)
api = Api(app, version='1.0', title='VulnHunter API',
          description='API для анализа CVE и генерации PoC',
          doc='/docs')  # Swagger UI будет доступен на /docs

analyze_input = api.model('AnalyzeInput', {
    'cve_text': fields.String(required=True, description='Описание CVE'),
    'patch_diff': fields.String(description='Патч diff'),
    'project_path': fields.String(required=True, description='Путь к проекту'),
    'exploit_type': fields.String(description='Тип эксплойта', default='RCE'),
    'language': fields.String(description='Язык PoC', default='python')
})

@api.route('/analyze')
class Analyze(Resource):
    @api.expect(analyze_input)
    @api.response(200, 'Успешно')
    def post(self):
        data = api.payload
        cve_text = data.get("cve_text", "")
        patch_diff = data.get("patch_diff", "")
        project_path = data.get("project_path", "")
        exploit_type = data.get("exploit_type", "RCE")
        language = data.get("language", "python")

        parser = CVEParser()
        cve_info = parser.parse_cve_and_patch(cve_text, patch_diff)

        dep_files = find_dependency_files(project_path)
        dependencies = {}
        for dep_file in dep_files:
            if dep_file.endswith("requirements.txt"):
                dependencies.update(parse_requirements_txt(dep_file))

        analyzer = CodeAnalyzer()
        vuln_func = cve_info.get("function")

        found = []
        if vuln_func:
            py_file = os.path.join(project_path, cve_info.get("file"))
            if os.path.isfile(py_file):
                found = analyzer.find_vulnerable_calls(py_file, [vuln_func])

        poc_gen = PoCGenerator()
        poc = poc_gen.generate_poc(cve_info, exploit_type, language)

        return {
            "cve_info": cve_info,
            "dependencies": dependencies,
            "vuln_calls": found,
            "poc": poc
        }

if __name__ == "__main__":
    app.run(debug=True)