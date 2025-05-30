#import os
#from langchain.embeddings import AzureOpenAIEmbeddings
#embeddings = AzureOpenAIEmbeddings(
 # model="text-embedding-ada-002",
  #azure_endpoint="https://aoai-farm.bosch-temp.com/api",
  #openai_api_key="dummy",  # required but not used
  #openai_api_type="azure",
  #openai_api_version="2023-05-15",
  #azure_deployment="askbosch-prod-farm-openai-text-embedding-ada-002",
  #default_headers={"genaiplatform-farm-subscription-key": os.getenv("LLMFARM_API_KEY")}
#)

from langchain_openai import AzureOpenAIEmbeddings

# Initialize the embeddings client
embeddings = AzureOpenAIEmbeddings(
    azure_endpoint="https://aoai-farm.bosch-temp.com/api",
    api_key="40ed81f7152040b7ac724ad59379849b",
    api_version="2023-05-15",
    deployment="askbosch-prod-farm-openai-text-embedding-ada-002"
)

# Example usage
texts = ["Hello world", "How are you today?"]
embedded_vectors = embeddings.embed_documents(texts)

# Print the embedding vectors
for i, vec in enumerate(embedded_vectors):
    print(f"Text: {texts[i]}")
    print(f"Vector: {vec[:5]}... (length: {len(vec)})\n")  # print first 5 dimensions for brevity
