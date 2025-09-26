from pathlib import Path
from typing import Optional

from flask import Flask
from flask_restx import Api, Resource, fields, Namespace
from cve_parser.parser import CVEParser
from code_analyzer.analyzer import CodeAnalyzer
from code_analyzer.dependencies import parse_requirements_txt, find_dependency_files
from poc_generator.generator import PoCGenerator
import os
import uuid

from poc_generator.rag_generator import ContextFileRAG

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='VulnHunter API (Pipeline)',
    description='Пошаговый API: парсинг CVE -> анализ зависимостей -> поиск уязвимых вызовов -> генерация PoC',
    doc='/docs'
)
# создаём свой namespace (название влияет на тег в Swagger)
ns = Namespace('01 Pipeline', description='Парсинг CVE → Зависимости → Поиск → PoC')
api.add_namespace(ns, path='/')  # базовый путь для всех роутов в этом ns
# Простое in-memory хранилище пайплайнов (для продакшна используйте Redis/БД)
PIPELINES = {}

# ======= Schemas (Models) =======

start_pipeline_input = api.model('StartPipelineInput', {
    'cve_text': fields.String(required=True, description='Описание CVE'),
    'patch_diff': fields.String(description='Патч diff'),
    'project_path': fields.String(required=True, description='Путь к проекту'),
    'exploit_type': fields.String(description='Тип эксплойта', default='RCE'),
    'language': fields.String(description='Язык PoC', default='python')
})

parse_cve_input = api.model('ParseCVEInput', {
    'pipeline_id': fields.String(required=True, description='ID пайплайна')
})

detect_deps_input = api.model('DetectDepsInput', {
    'pipeline_id': fields.String(required=True, description='ID пайплайна')
})

find_calls_input = api.model('FindCallsInput', {
    'pipeline_id': fields.String(required=True, description='ID пайплайна')
})

generate_poc_input = api.model('GeneratePoCInput', {
    'pipeline_id': fields.String(required=True, description='ID пайплайна')
})

get_exploit_input = api.model('GetExploitInput', {
    'pipeline_id': fields.String(required=True, description='ID пайплайна')
})

# ======= Helpers =======

def get_pipeline_or_404(pipeline_id: str):
    pipeline = PIPELINES.get(pipeline_id)
    if not pipeline:
        api.abort(404, f"Pipeline {pipeline_id} not found")
    return pipeline

# ======= Endpoints (пронумерованные пути для упорядочивания в Swagger) =======

@ns.route('/1-pipeline/start')
class StartPipeline(Resource):
    @ns.expect(start_pipeline_input, validate=True)
    @ns.response(201, 'Пайплайн создан')
    def post(self):
        data = api.payload
        pipeline_id = str(uuid.uuid4())

        PIPELINES[pipeline_id] = {
            'params': {
                'cve_text': data.get('cve_text', ''),
                'patch_diff': data.get('patch_diff', ''),
                'project_path': data.get('project_path', ''),
                'exploit_type': data.get('exploit_type', 'RCE'),
                'language': data.get('language', 'python'),
            },
            'cve_info': None,
            'dependencies': None,
            'vuln_calls': None,
            'poc': None,
            'status': 'created'
        }

        return {
            'pipeline_id': pipeline_id,
            'status': 'created',
            'next': '/2-parse-cve'
        }, 201


@ns.route('/2-parse-cve')
class ParseCVE(Resource):
    @ns.expect(parse_cve_input, validate=True)
    @ns.response(200, 'CVE распарсен')
    def post(self):
        pipeline_id = api.payload['pipeline_id']
        p = get_pipeline_or_404(pipeline_id)
        params = p['params']

        parser = CVEParser()
        cve_info = parser.parse_cve_and_patch(params['cve_text'], params.get('patch_diff', ''))

        p['cve_info'] = cve_info
        p['status'] = 'cve_parsed'

        return {
            'pipeline_id': pipeline_id,
            'cve_info': cve_info,
            'next': '/3-detect-dependencies'
        }


@ns.route('/3-detect-dependencies')
class DetectDependencies(Resource):
    @ns.expect(detect_deps_input, validate=True)
    @ns.response(200, 'Зависимости обнаружены')
    def post(self):
        pipeline_id = api.payload['pipeline_id']
        p = get_pipeline_or_404(pipeline_id)
        params = p['params']

        project_path = params['project_path']
        dep_files = find_dependency_files(project_path)
        dependencies = {}
        for dep_file in dep_files:
            if dep_file.endswith("requirements.txt"):
                dependencies.update(parse_requirements_txt(dep_file))

        p['dependencies'] = dependencies
        p['status'] = 'dependencies_detected'

        return {
            'pipeline_id': pipeline_id,
            'dependencies': dependencies,
            'next': '/4-find-vuln-calls'
        }


@ns.route('/4-find-vuln-calls')
class FindVulnCalls(Resource):
    @ns.expect(find_calls_input, validate=True)
    @ns.response(200, 'Уязвимые вызовы найдены')
    def post(self):
        pipeline_id = api.payload['pipeline_id']
        p = get_pipeline_or_404(pipeline_id)
        params = p['params']
        cve_info = p.get('cve_info') or {}

        analyzer = CodeAnalyzer()
        vuln_func = cve_info.get("function")
        found = []

        if vuln_func:
            file_rel = cve_info.get("file")
            if file_rel:
                py_file = os.path.join(params['project_path'], file_rel)
                if os.path.isfile(py_file):
                    found = analyzer.find_vulnerable_calls(py_file, [vuln_func])

        p['vuln_calls'] = found
        p['status'] = 'vuln_calls_found'

        return {
            'pipeline_id': pipeline_id,
            'vuln_calls': found,
            'next': '/5-generate-poc'
        }


@ns.route('/5-generate-poc')
class GeneratePoC(Resource):
    @ns.expect(generate_poc_input, validate=True)
    @ns.response(200, 'PoC сгенерирован')
    def post(self):
        pipeline_id = api.payload['pipeline_id']
        p = get_pipeline_or_404(pipeline_id)
        params = p['params']
        cve_info = params.get('cve_text') or {}

        poc_gen = PoCGenerator()
        poc = poc_gen.generate_poc(
            cve_info,
            params.get('exploit_type', 'RCE'),
            params.get('language', 'python')
        )

        p['poc'] = poc
        p['status'] = 'poc_generated'

        return {
            'pipeline_id': pipeline_id,
            'poc': poc,
            'done': True
        }


@ns.route('/6-pipeline/<string:pipeline_id>')
class PipelineState(Resource):
    @ns.response(200, 'Состояние пайплайна')
    def get(self, pipeline_id):
        p = get_pipeline_or_404(pipeline_id)
        return {
            'pipeline_id': pipeline_id,
            'status': p['status'],
            'params': p['params'],
            'cve_info': p['cve_info'],
            'dependencies': p['dependencies'],
            'vuln_calls': p['vuln_calls'],
            'poc': p['poc']
        }

RAG_INDEX = None  # лениво инициализируем общий индекс на процесс

def _get_rag_index() -> "ContextFileRAG":
    global RAG_INDEX
    if RAG_INDEX is None:
        # Путь к файлу rag.txt рядом с текущим модулем (или поменяйте на нужный)
        json_txt_path = Path(__file__).resolve().parent / "poc_generator/rag.txt"
        if not json_txt_path.is_file():
            raise FileNotFoundError(f"RAG corpus not found: {json_txt_path}")
        RAG_INDEX = ContextFileRAG.from_json_file(
            json_txt_path=str(json_txt_path),
            max_chunk_chars=400,
            overlap_chars=0,
            paragraph_mode=True,
        )
    return RAG_INDEX

def _build_query_from_context(context: dict) -> Optional[str]:
    """
    Формируем запрос к RAG. Сначала пробуем CVE, затем короткое имя/название,
    затем краткое описание. Если всё пусто — вернём None.
    """
    if not context:
        return None
    for key in ("CVE-", "name", "short_description", "description"):
        val = context.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None

@ns.route('/7-get-exploit')
class GetExploit(Resource):
    @ns.expect(get_exploit_input, validate=True)
    @ns.response(200, 'Эксплойт найден и возвращён')
    @ns.response(404, 'Эксплойт не найден')
    def post(self):
        pipeline_id = api.payload['pipeline_id']
        p = get_pipeline_or_404(pipeline_id)

        context = p.get('cve_info')  # контекст по CVE (dict с полями cve_id/name/short_description/…)
        exploit = p.get('poc')       # PoC/эксплойт, если уже был найден ранее

        # Если PoC ещё не сгенерирован предыдущим шагом — пытаемся извлечь его из локального RAG
        if not exploit:
            # Строим запрос для RAG
            #query = _build_query_from_context(context) or api.payload.get('query') or ""
            query = p.get('params').get('cve_text')
            if not query:
                api.abort(404, f"Exploit for pipeline {pipeline_id} not found and query is empty.")

            rag = _get_rag_index()
            # generate_answer уже возвращает только кусок после маркера "Пример эксплуатации (без вредоносной нагрузки):"
            result = rag.generate_answer(
                question=query,
                top_k=1,
                max_context_chars=10000,
                return_debug=True,
            )
            exploit = (result.get("answer") or "").strip()
            if not exploit:
                api.abort(404, f"Exploit for pipeline {pipeline_id} not found in local RAG for query: {query}")

            # Сохраняем PoC и debug в pipeline для повторного использования
            p['poc'] = exploit
            p['rag_debug'] = result.get("debug", "")

        # Обновляем статус для наглядности
        p['status'] = 'exploit_returned'

        return {
            'pipeline_id': pipeline_id,
            'context': context,   # контекст, связанный с уязвимостью
            'exploit': exploit,   # соответствующий эксплойт из локального RAG/хранилища
            'done': True
        }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)