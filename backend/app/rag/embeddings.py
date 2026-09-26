from sentence_transformers import SentenceTransformer


MODEL_NAME = "all-MiniLM-L6-v2"

model = SentenceTransformer(MODEL_NAME)


def embed_texts(texts):
    return model.encode(
        texts,
        normalize_embeddings=True
    )


if __name__ == "__main__":
    texts = [
        "Suricata detects network security threats.",
        "Zeek provides network telemetry."
    ]

    embeddings = embed_texts(texts)

    print(f"Model: {MODEL_NAME}")
    print(f"Embeddings shape: {embeddings.shape}")
