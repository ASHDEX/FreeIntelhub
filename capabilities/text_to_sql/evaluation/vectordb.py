import json
import os

import numpy as np
import voyageai


class VectorDB:
    def __init__(self, db_path="../data/vector_db.npz"):
        self.client = voyageai.Client(api_key=os.getenv("VOYAGE_API_KEY"))
        self.db_path = db_path
        self.load_db()

    def load_db(self):
        if os.path.exists(self.db_path):
            data = np.load(self.db_path, allow_pickle=False)
            self.embeddings = data["embeddings"].tolist()
            self.metadata = json.loads(str(data["metadata"]))
            self.query_cache = json.loads(str(data["query_cache"]))
        else:
            self.embeddings, self.metadata, self.query_cache = [], [], {}

    def load_data(self, data):
        if not self.embeddings:
            texts = [item["text"] for item in data]
            self.embeddings = [
                emb
                for batch in range(0, len(texts), 128)
                for emb in self.client.embed(
                    texts[batch : batch + 128], model="voyage-2"
                ).embeddings
            ]
            self.metadata = [item["metadata"] for item in data]  # Store only the inner metadata
            self.save_db()

    def search(self, query, k=5, similarity_threshold=0.3):
        if query not in self.query_cache:
            self.query_cache[query] = self.client.embed([query], model="voyage-2").embeddings[0]
            self.save_db()

        similarities = np.dot(self.embeddings, self.query_cache[query])
        top_indices = np.argsort(similarities)[::-1]

        return [
            {"metadata": self.metadata[i], "similarity": similarities[i]}
            for i in top_indices
            if similarities[i] >= similarity_threshold
        ][:k]

    def save_db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        np.savez(
            self.db_path,
            embeddings=np.array(self.embeddings) if self.embeddings else np.empty(0),
            metadata=np.array(json.dumps(self.metadata)),
            query_cache=np.array(json.dumps(self.query_cache)),
        )
