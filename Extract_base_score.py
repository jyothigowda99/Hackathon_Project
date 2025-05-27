import requests
import json
from openai import OpenAI
# Create LLM client using custom Azure OpenAI endpoint
llmClient = OpenAI(
    api_key="dummy",  # Overwritten by API manager
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={"genaiplatform-farm-subscription-key": "40ed81f7152040b7ac724ad59379849b"}
)

# Query LLM with a given prompt
def queryLLM(promptQuery, model_name="gpt-4o-mini"):
    try:
        completion = llmClient.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": promptQuery}],
            extra_query={"api-version": "2024-08-01-preview"},
            temperature=0.8
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"An error occurred during LLM query: {e}"


# Fetch CVE info from NVD API and save to JSON
def fetch_cve_data_and_save(cve_id):
    API_KEY = 'fbcb6fee-ef22-4e0a-b5cb-b87df08d7fd1'.strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": API_KEY}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        filename = f"{cve_id}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"✅ CVE JSON saved as {filename}")
        return data
    except Exception as e:
        return {"error": str(e)}

# Extract CVSS data
def extract_cvss(metrics):
    for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if key in metrics:
            return metrics[key][0].get('cvssData', {})
    return {}

# Extract baseScore from stored JSON file
def extract_base_score_from_json(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        metrics = data['vulnerabilities'][0]['cve'].get('metrics', {})
        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if key in metrics:
                return metrics[key][0]['cvssData'].get('baseScore', "Base score not found")
        return "CVSS data not available"
    except Exception as e:
        return f"Error reading/parsing JSON: {e}"

# Format prompt for LLM
def format_cve_prompt(cve_id, cve_data):
    try:
        item = cve_data['vulnerabilities'][0]['cve']
        desc = item.get('descriptions', [{}])[0].get('value', 'No description available.')
        metrics = item.get('metrics', {})
        cvss_data = extract_cvss(metrics)
        score = cvss_data.get('baseScore', 'N/A')
        severity = cvss_data.get('baseSeverity', 'N/A')

        prompt = (
            f"Provide a security analysis for {cve_id}.\n\n"
            f"Description: {desc}\n"
            f"CVSS Score: {score} ({severity})\n"
            f"Include impacted systems, exploitation methods, and mitigation strategies."
        )
        return prompt
    except Exception as e:
        return f"Error formatting CVE prompt: {e}"

# Analyze a CVE using LLM
def analyze_cve(cve_id):
    cve_data = fetch_cve_data_and_save(cve_id)
    if "error" in cve_data:
        return f"❌ Failed to retrieve CVE: {cve_data['error']}"

    prompt = format_cve_prompt(cve_id, cve_data)
    if prompt.startswith("Error"):
        return prompt

    response = queryLLM(prompt)
    return response

# Main
if __name__ == "__main__":
    cve_id = "CVE-2023-0464"
    print("🧠 LLM Analysis:")
    print(analyze_cve(cve_id))

    print("\n📊 Extracted baseScore from saved JSON:")
    base_score = extract_base_score_from_json(f"{cve_id}.json")
    print(f"Base Score: {base_score}")