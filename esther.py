import os
import pandas as pd
from dotenv import load_dotenv

from langchain_openai import AzureOpenAIEmbeddings, AzureChatOpenAI
from langchain_community.vectorstores import FAISS
from langchain.docstore.document import Document
from langchain.text_splitter import CharacterTextSplitter
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnableParallel, RunnableLambda

#from config.settings import DATA_PATH, VECTOR_STORE_PATH

DATA_PATH = os.path.join("data", "SRA.xlsm")
VECTOR_STORE_PATH = os.path.join("vectorstore", "faiss_index")
OPENAI_MODEL = "gpt-3.5-turbo"

# === Load environment variables ===
load_dotenv()
OPENAI_API_KEY = os.getenv("40ed81f7152040b7ac724ad59379849b")
END_POINT = os.getenv("https://xplatform-openai-shared.openai.azure.com/")
MODEL = os.getenv("text-embedding-ada-002")
API_VERSION = os.getenv("2023-05-15")

# === Step 1: Create Embeddings ===
embedding = AzureOpenAIEmbeddings(
    chunk_size=500,
    model=MODEL,
    azure_endpoint=END_POINT,
    api_key=OPENAI_API_KEY,
)

# === Step 2: Load Excel File ===
df = pd.read_excel(DATA_PATH, engine="openpyxl")

# Convert rows to text documents
documents = [
    Document(page_content=" | ".join(map(str, row)), metadata={"row_index": idx})
    for idx, row in df.iterrows()
]

# === Step 3: Optional Splitting ===
splitter = CharacterTextSplitter(chunk_size=500, chunk_overlap=50)
split_docs = splitter.split_documents(documents)

# === Step 4: Create and Save FAISS Vector Store ===
vectorstore = FAISS.from_documents(split_docs, embedding)
vectorstore.save_local(VECTOR_STORE_PATH)

# === Step 5: Load Vector Store and Create Retriever ===
vectorstore = FAISS.load_local(
    VECTOR_STORE_PATH,
    embeddings=embedding,
    allow_dangerous_deserialization=True  # Use with caution
)
retriever = vectorstore.as_retriever(search_type="mmr", search_kwargs={"k": len(documents)})

# === Step 6: Define Prompt Template ===
prompt_template = """
You are a cybersecurity analyst AI with expertise in analyzing and providing insights of CVE.
You have been given the following CVE IDs from a vulnerability database:

CVE:
{cve_ids}

Context:
{context}

Based on the above CVE IDs:

1. Get the vector string from nvd and analyze each parameter like AV,AC,UI,C,I,A and so on
2. Correlate these parameters with the "hints to the Question" column in the SRA document.
3. Based on the asked question, give the cybersecurity criticality of the project.

Respond in a clear, structured format with headings:
- Critical level
- Vector string of CVE 3.x version


"""

prompt = PromptTemplate.from_template(prompt_template)

# === Step 7: Setup LLM ===
llm = AzureChatOpenAI(
    deployment_name="gpt-4",
    openai_api_key=OPENAI_API_KEY,
    azure_endpoint=END_POINT,
    openai_api_version=API_VERSION,
    model_name="gpt-4"
)

# === Step 8: Define RAG Chain ===
def format_prompt(inputs):
    return prompt.format(
        cve_ids=inputs["cve_ids"],
        context="\n".join([doc.page_content for doc in inputs["context"]])
    )

rag_chain = RunnableParallel(
    {
        "context": lambda x: retriever.get_relevant_documents(x["query"]),
        "cve_ids": lambda x: x["cve_ids"]
    }
) | RunnableLambda(format_prompt) | llm

# === Step 9: Run the Chain ===
if __name__ == "__main__":
    query = input("Enter your question: ")
    cve_ids = "CVE-2022-0001"

    response = rag_chain.invoke({"query": query, "cve_ids": cve_ids})
    print(f"\n💡 Answer: {response.content}")