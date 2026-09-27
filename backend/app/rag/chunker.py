from .loader import load_documents


MIN_CHUNK_LENGTH = 80


def chunk_documents(documents):
    chunks = []

    for document in documents:
        content = document["content"].strip()

        sections = content.split("\n## ")

        buffer = ""

        for index, section in enumerate(sections):
            if index == 0:
                section_text = section
            else:
                section_text = "## " + section

            section_text = section_text.strip()

            if not section_text:
                continue

            combined = (buffer + "\n\n" + section_text).strip() if buffer else section_text

            if len(combined) < MIN_CHUNK_LENGTH:
                buffer = combined
                continue

            chunks.append({
                "source": document["source"],
                "content": combined,
            })

            buffer = ""

        if buffer:
            chunks.append({
                "source": document["source"],
                "content": buffer,
            })

    return chunks
