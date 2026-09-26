from .chunker import chunk_documents
from .embeddings import embed_texts
from .loader import load_documents


def build_embeddings():
    documents = load_documents()
    chunks = chunk_documents(documents)

    texts = [chunk["content"] for chunk in chunks]
    embeddings = embed_texts(texts)

    for chunk, embedding in zip(chunks, embeddings):
        chunk["embedding"] = embedding.tolist()

    return chunks


if __name__ == "__main__":
    chunks = build_embeddings()

    print(f"Generated embeddings for {len(chunks)} chunks")
    print(f"Embedding dimension: {len(chunks[0]['embedding'])}")

    for chunk in chunks[:3]:
        print(
            f"- {chunk['source']}: "
            f"{len(chunk['embedding'])} dimensions"
        )
