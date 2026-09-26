import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer


INDEX_PATH = Path(__file__).parent / "rag_index.json"
MODEL_NAME = "all-MiniLM-L6-v2"

model = SentenceTransformer(MODEL_NAME)


def load_index():
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def search(query, top_k=3):
    chunks = load_index()

    query_embedding = model.encode(
        query,
        normalize_embeddings=True
    )

    results = []

    for chunk in chunks:
        embedding = np.array(chunk["embedding"])

        score = float(
            np.dot(query_embedding, embedding)
        )

        results.append({
            "source": chunk["source"],
            "score": score,
            "content": chunk["content"],
        })

    results.sort(
        key=lambda result: result["score"],
        reverse=True
    )

    return results[:top_k]


if __name__ == "__main__":
    query = "What does a high number of failed connections indicate?"

    results = search(query)

    print(f"Query: {query}")

    for index, result in enumerate(results, start=1):
        print(
            f"\nResult {index}"
            f"\nSource: {result['source']}"
            f"\nScore: {result['score']:.4f}"
        )
        print(result["content"][:300].replace("\n", " "))

