import os
import re
import math
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


def tokenize(text: str) -> List[str]:
    # Простая токенизация: приведение к нижнему регистру и разбиение по неалфанумерическим символам
    return [t for t in re.split(r"[^\w]+", text.lower()) if t]


@dataclass
class Chunk:
    text: str
    tokens: List[str]


class ContextFileRAG:
    """
    Имитация RAG-хранилища, где весь контекст хранится в одном файле.
    Механизм:
      - Загружаем контекст из файла
      - Делаем простое чанкирование (по параграфам или по символам)
      - Строим простую TF-IDF модель по чанкам
      - На запрос находим top-k релевантных чанков и "подкладываем" их в промпт
      - Модель имитируется простым извлечением подходящих предложений из лучших чанков
    """

    def __init__(
        self,
        context_path: str,
        max_chunk_chars: int = 800,
        overlap_chars: int = 100,
        paragraph_mode: bool = True,  # True: резать по параграфам, False: по окнам символов
    ):
        if not os.path.isfile(context_path):
            raise FileNotFoundError(f"Context file not found: {context_path}")
        self.context_path = context_path
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = overlap_chars
        self.paragraph_mode = paragraph_mode

        self.raw_context: str = self._load_context()
        self.chunks: List[Chunk] = self._make_chunks(self.raw_context)
        self.idf: Dict[str, float] = self._compute_idf(self.chunks)

    def _load_context(self) -> str:
        with open(self.context_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def _split_paragraphs(self, text: str) -> List[str]:
        # Разделяем по двум и более переводам строк как по параграфам
        paragraphs = re.split(r"\n\s*\n", text.strip())
        # Нормализуем переносы строк внутри параграфов
        return [re.sub(r"[ \t]+\n", "\n", p.strip()) for p in paragraphs if p.strip()]

    def _sliding_windows(self, text: str) -> List[str]:
        # Скользящее окно по символам
        res = []
        i = 0
        n = len(text)
        while i < n:
            j = min(i + self.max_chunk_chars, n)
            res.append(text[i:j])
            if j == n:
                break
            i = max(j - self.overlap_chars, i + 1)
        return [s.strip() for s in res if s.strip()]

    def _chunk_long_paragraph(self, p: str) -> List[str]:
        if len(p) <= self.max_chunk_chars:
            return [p]
        # Если параграф слишком длинный — дробим его скользящими окнами
        return self._sliding_windows(p)

    def _make_chunks(self, text: str) -> List[Chunk]:
        raw_chunks: List[str] = []
        if self.paragraph_mode:
            for p in self._split_paragraphs(text):
                raw_chunks.extend(self._chunk_long_paragraph(p))
        else:
            raw_chunks.extend(self._sliding_windows(text))

        chunks = [Chunk(text=c, tokens=tokenize(c)) for c in raw_chunks]
        # Удаляем пустые по токенам
        return [c for c in chunks if c.tokens]

    def _compute_idf(self, chunks: List[Chunk]) -> Dict[str, float]:
        # Документ — это чанк
        N = len(chunks)
        df: Dict[str, int] = {}
        for ch in chunks:
            for t in set(ch.tokens):
                df[t] = df.get(t, 0) + 1
        idf = {}
        for t, d in df.items():
            # Сглажённый idf
            idf[t] = math.log((N + 1) / (d + 0.5)) + 1.0
        return idf

    def _tf(self, tokens: List[str]) -> Dict[str, float]:
        tf: Dict[str, float] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1.0
        # Нормируем на длину
        total = sum(tf.values()) or 1.0
        for t in tf:
            tf[t] /= total
        return tf

    def _tfidf_vec(self, tokens: List[str]) -> Dict[str, float]:
        tf = self._tf(tokens)
        return {t: tf[t] * self.idf.get(t, 0.0) for t in tf}

    @staticmethod
    def _cosine_sim(a: Dict[str, float], b: Dict[str, float]) -> float:
        # Косинус для разреженных словарей
        if not a or not b:
            return 0.0
        dot = 0.0
        for t, v in a.items():
            bv = b.get(t)
            if bv is not None:
                dot += v * bv
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (na * nb)

    def retrieve(self, query: str, top_k: int = 5) -> List[Tuple[Chunk, float]]:
        q_tokens = tokenize(query)
        q_vec = self._tfidf_vec(q_tokens)

        scored: List[Tuple[int, float]] = []
        for i, ch in enumerate(self.chunks):
            ch_vec = self._tfidf_vec(ch.tokens)
            s = self._cosine_sim(q_vec, ch_vec)
            if s > 0.0:
                scored.append((i, s))

        scored.sort(key=lambda x: x[1], reverse=True)
        results: List[Tuple[Chunk, float]] = [(self.chunks[i], score) for i, score in scored[:top_k]]
        return results

    @staticmethod
    def _extract_relevant_sentences(text: str, query: str, max_sentences: int = 4) -> List[str]:
        # Грубое разбиение на предложения
        sents = re.split(r"(?<=[\.\?\!])\s+", text.strip())
        q_tokens = set(tokenize(query))
        # Оценим каждое предложение по доле пересечения токенов
        scored = []
        for s in sents:
            st = set(tokenize(s))
            if not st:
                continue
            overlap = len(st & q_tokens)
            if overlap == 0:
                continue
            score = overlap / (len(st) ** 0.5)
            scored.append((s, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [s for s, _ in scored[:max_sentences]]

    def generate_answer(
            self,
            question: str,
            top_k: int = 5,
            max_context_chars: int = 1500,
            return_debug: bool = False,
    ) -> Dict[str, str]:
        """
        Возвращает только часть контекста после маркера:
        'Пример эксплуатации (без вредоносной нагрузки):'
        Для каждого релевантного чанка извлекается подстрока от маркера и далее
        (по возможности обрезается до 'Примечание:'), затем склеивается в общий контекст,
        ограниченный max_context_chars.
        """
        marker = "Пример эксплуатации (без вредоносной нагрузки):"
        end_markers = ["Примечание:", "Примечания:"]

        retrieved = self.retrieve(question, top_k=top_k)
        if not retrieved:
            return {
                "answer": "Не удалось найти релевантный контекст для ответа.",
                "context": "",
                "debug": json.dumps({"scores": []}, ensure_ascii=False) if return_debug else "",
            }

        def extract_after_marker(text: str) -> str:
            start = text.find(marker)
            if start == -1:
                return ""  # строго требуем только часть после маркера
            start += len(marker)
            tail = text[start:].lstrip("\n\r ")

            # Обрежем по ближайшему из конечных маркеров (если он есть)
            cut_pos = None
            for em in end_markers:
                pos = tail.find(em)
                if pos != -1:
                    cut_pos = pos if cut_pos is None else min(cut_pos, pos)
            if cut_pos is not None:
                tail = tail[:cut_pos].rstrip()

            return tail

        snippets: List[str] = []
        debug_scores = []
        for ch, score in retrieved:
            debug_scores.append({
                "score": round(score, 4),
                "snippet": ch.text[:120] + ("..." if len(ch.text) > 120 else "")
            })
            part = extract_after_marker(ch.text)
            if part:
                snippets.append(part)

        if not snippets:
            return {
                "answer": "Контекст найден, но в нём нет секции после требуемого маркера.",
                "context": "",
                "debug": json.dumps({"scores": debug_scores}, ensure_ascii=False) if return_debug else "",
            }

        # Ограничим размер "подгружаемого в модель" контекста
        context = ""
        for s in snippets:
            if len(context) + len(s) + 2 > max_context_chars:
                # Если текущий фрагмент слишком большой, попробуем частично его добавить
                remaining = max_context_chars - len(context) - 2
                if remaining > 0:
                    context += s[:remaining]
                break
            context += (s + "\n\n")

        # Ответом возвращаем именно извлечённый кусок(и), без дополнительной постобработки
        answer = context.strip() if context.strip() else "Контекст найден, но не удалось извлечь нужный фрагмент."

        out = {
            "answer": answer,
            "context": answer,  # дублируем для удобства: и 'answer', и 'context' содержат только нужный кусок
        }
        if return_debug:
            out["debug"] = json.dumps({"scores": debug_scores}, ensure_ascii=False)
        return out


def build_corpus_from_json(entries):
    """
    Преобразует список объектов (из JSON) в одно текстовое полотно для индексации RAG.
    Каждую запись разворачиваем в читабельный блок.
    """
    parts = []
    for e in entries:
        cve = e.get("cve_id", "")
        name = e.get("name", "")
        desc = e.get("short_description", "")
        tags = ", ".join(e.get("tags", []))

        vuln = e.get("vulnerable_code", {}) or {}
        vuln_lang = vuln.get("language", "")
        vuln_file = vuln.get("filename", "")
        vuln_code = vuln.get("code", "")

        exp = e.get("exploit_example", {}) or {}
        exp_lang = exp.get("language", "")
        exp_file = exp.get("filename", "")
        exp_code = exp.get("code", "")
        exp_note = exp.get("note", "")

        block = [
            f"CVE: {cve}",
            f"Название: {name}",
            f"Описание: {desc}",
            f"Теги: {tags}" if tags else "",
            "Уязвимый код:",
            f"- Язык: {vuln_lang}",
            f"- Файл: {vuln_file}",
            vuln_code.strip() if vuln_code else "",
            "Пример эксплуатации (без вредоносной нагрузки):",
            f"- Язык: {exp_lang}",
            f"- Файл: {exp_file}",
            exp_code.strip() if exp_code else "",
            f"Примечание: {exp_note}" if exp_note else "",
        ]
        parts.append("\n".join([line for line in block if line]))
    return "\n\n-----\n\n".join(parts)


import json
import math
from pathlib import Path
from typing import List, Dict

# Предполагается, что у вас уже есть:
# - функция tokenize(text: str) -> List[str]
# - dataclass Chunk(text: str, tokens: List[str])
# - класс ContextFileRAG (мы расширим его классовым методом)

def render_entry_to_text(e: Dict) -> str:
    """Разворачивает один JSON-объект в «читабельный» текст чанка."""
    cve = e.get("cve_id", "")
    name = e.get("name", "")
    desc = e.get("short_description", "")
    tags = ", ".join(e.get("tags", []))

    vuln = e.get("vulnerable_code", {}) or {}
    vuln_lang = vuln.get("language", "")
    vuln_file = vuln.get("filename", "")
    vuln_code = vuln.get("code", "")

    exp = e.get("exploit_example", {}) or {}
    exp_lang = exp.get("language", "")
    exp_file = exp.get("filename", "")
    exp_code = exp.get("code", "")
    exp_note = exp.get("note", "")

    lines = [
        f"CVE: {cve}" if cve else "",
        f"Название: {name}" if name else "",
        f"Описание: {desc}" if desc else "",
        f"Теги: {tags}" if tags else "",
        "Уязвимый код:",
        f"- Язык: {vuln_lang}" if vuln_lang else "",
        f"- Файл: {vuln_file}" if vuln_file else "",
        vuln_code.strip() if vuln_code else "",
        "Пример эксплуатации (без вредоносной нагрузки):",
        f"- Язык: {exp_lang}" if exp_lang else "",
        f"- Файл: {exp_file}" if exp_file else "",
        exp_code.strip() if exp_code else "",
        f"Примечание: {exp_note}" if exp_note else "",
    ]
    return "\n".join([ln for ln in lines if ln])

def load_chunks_from_json_file(json_txt_path: str) -> List["Chunk"]:
    """
    Загружает JSON-массив из файла и возвращает список чанков,
    где каждый элемент массива — отдельный чанк (один JSON-объект = один чанк).
    """
    data = Path(json_txt_path).read_text(encoding="utf-8").strip()
    entries = json.loads(data)
    if not isinstance(entries, list):
        raise ValueError("Ожидался JSON-массив (list) объектов.")

    chunks: List["Chunk"] = []
    for e in entries:
        text = render_entry_to_text(e)
        tokens = tokenize(text)
        chunks.append(Chunk(text=text, tokens=tokens))
    return chunks

def _build_df_local(chunks: List["Chunk"]) -> Dict[str, int]:
    """Считает document frequency для токенов."""
    df: Dict[str, int] = {}
    for ch in chunks:
        for tok in set(ch.tokens):
            df[tok] = df.get(tok, 0) + 1
    return df

def _compute_idf_local(N: int, df: Dict[str, int]) -> Dict[str, float]:
    """Считает IDF по BM25 (с сглаживанием)."""
    idf: Dict[str, float] = {}
    for tok, d in df.items():
        idf[tok] = math.log((N - d + 0.5) / (d + 0.5) + 1.0)
    return idf

class ContextFileRAG(ContextFileRAG):  # type: ignore[name-defined]
    @classmethod
    def from_json_file(
        cls,
        json_txt_path: str,
        max_chunk_chars: int = 800,
        overlap_chars: int = 100,
        paragraph_mode: bool = True,
    ) -> "ContextFileRAG":
        """
        Создаёт индекс так, чтобы каждый JSON-объект из файла стал отдельным чанком.
        Параметры разбиения символами не используются — чанк уже готов.
        """
        # Создаём инстанс без вызова __init__, чтобы не грузить текстовый файл
        self = cls.__new__(cls)  # type: ignore[misc]

        # Базовые поля (если ваш класс их ожидает)
        self.context_path = json_txt_path
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = overlap_chars
        self.paragraph_mode = paragraph_mode

        # Формируем чанки из JSON
        self.chunks = load_chunks_from_json_file(json_txt_path)

        # Индексные статистики (без использования отсутствующих _build_df/_compute_idf)
        self.N = max(len(self.chunks), 1)
        self.df_cache = _build_df_local(self.chunks)
        self.idf = _compute_idf_local(self.N, self.df_cache)
        self.idf_floor = math.log((self.N + 1) / 0.5) + 1.0
        total_len = sum(len(ch.tokens) for ch in self.chunks)
        self.avg_len = (total_len / self.N) if self.N else 0.0

        return self

# Пример использования:
# if __name__ == "__main__":
#     # Один JSON-объект = один чанк. Путь к файлу с JSON-массивом:
#     json_txt_path = "rag.txt"
#
#     rag = ContextFileRAG.from_json_file(
#         json_txt_path=json_txt_path,
#         max_chunk_chars=400,
#         overlap_chars=0,      # оверлап не нужен — чанки уже разделены по объектам
#         paragraph_mode=True,
#     )
#
#     # Вопросы к индексу
#     questions = [
#         "Опиши уязвимость CVE-2016-10033 и её проявление в PHPMailer.",
#         "CVE-2014-0160 (Heartbleed)",
#     ]
#
#     for q in questions:
#         result = rag.generate_answer(q, top_k=1, max_context_chars=10000, return_debug=True)
#         print("\nВопрос:", q)
#         print("Ответ:", result["answer"])
#         print("Контекст, подгруженный в модель:\n", result["context"])
#         print("Debug:", result.get("debug", ""))