from .loader import load_documents


def chunk_documents(documents):
    chunks = []

    for document in documents:
        content = document["content"].strip()

        sections = content.split("\n## ")

        for index, section in enumerate(sections):
            if index == 0:
                section_text = section
            else:
                section_text = "## " + section

            section_text = section_text.strip()

            if not section_text:
                continue

            chunks.append({
                "source": document["source"],
                "content": section_text,
            })

    return chunks


if __name__ == "__main__":
    documents = load_documents()
    chunks = chunk_documents(documents)

    print(f"Loaded documents: {len(documents)}")
    print(f"Generated chunks: {len(chunks)}")

    for index, chunk in enumerate(chunks[:10], start=1):
        print(
            f"\nChunk {index} "
            f"({chunk['source']}, {len(chunk['content'])} characters)"
        )
        print(chunk["content"][:300].replace("\n", " "))
