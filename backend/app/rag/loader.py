from pathlib import Path


KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


def load_documents():
    documents = []

    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        content = path.read_text(encoding="utf-8")

        documents.append({
            "source": path.name,
            "content": content,
        })

    return documents


if __name__ == "__main__":
    documents = load_documents()

    print(f"Loaded {len(documents)} documents")

    for document in documents:
        print(f"- {document['source']}: {len(document['content'])} characters")
