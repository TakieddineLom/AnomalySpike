import json
from pathlib import Path

from .indexer import build_embeddings


INDEX_PATH = Path(__file__).parent / "rag_index.json"


def build_index():
    chunks = build_embeddings()

    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False, indent=2)

    return chunks


if __name__ == "__main__":
    chunks = build_index()

    print(f"Saved {len(chunks)} chunks")
    print(f"Index: {INDEX_PATH}")

