import os
import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from openai import OpenAI

model = SentenceTransformer('all-MiniLM-L6-v2')

def load_excel_data(path: str) -> list[str]:
    df_raw = pd.read_excel(path, sheet_name='Assessment', skiprows=3)
    df_raw = df_raw.rename(columns={
        df_raw.columns[0]: 'ID',
        df_raw.columns[1]: 'Question',
        df_raw.columns[2]: 'Answer',
        df_raw.columns[3]: 'Remarks',
        df_raw.columns[4]: 'Status',
        df_raw.columns[5]: 'Hint'
    })
    df = df_raw.dropna(subset=['Question', 'Answer'])
    return df.apply(lambda row: f"Question: {row['Question']}\nAnswer: {row['Answer']}\nHint: {row['Hint']}", axis=1).tolist()

def query_llm(promptQuery, model_name="gpt-4o-mini"):
    try:
        client = OpenAI(
            api_key="dummy",  # Required but not used due to custom header
            base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
            default_headers={"genaiplatform-farm-subscription-key": "40ed81f7152040b7ac724ad59379849b"
        }            
        )
        completion = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": promptQuery}],
            extra_query={"api-version": "2024-08-01-preview"},
            temperature=0.7,
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error querying LLM: {e}"

def generate_answer(query: str, file_path: str, top_k=3) -> str:
    texts = load_excel_data(file_path)
    embeddings = model.encode(texts, convert_to_numpy=True)
    query_vec = model.encode([query], convert_to_numpy=True)
    similarities = cosine_similarity(query_vec, embeddings)[0]
    top_indices = np.argsort(similarities)[-top_k:][::-1]
    retrieved = [texts[i] for i in top_indices]
    context = "\n---\n".join(retrieved)

    prompt = f"""You are a cybersecurity assistant. Based on the following relevant context from a security assessment, answer the user's question.

Context:
{context}

Question: {query}
Answer:"""
    return query_llm(prompt)
