from docx import Document


def extract_docx_text(filepath: str) -> str:
    try:
        doc = Document(filepath)
        return "\n".join(p.text for p in doc.paragraphs if p.text)
    except Exception as e:
        return f"DOCX_READ_ERROR: {e}"