import requests
from openai import OpenAI
import json
import pandas as pd

# Create LLM client using custom Azure OpenAI endpoint
llmClient = OpenAI(
    api_key="dummy",  # Overwritten by API manager
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={"genaiplatform-farm-subscription-key":"40ed81f7152040b7ac724ad59379849b"}
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

# Fetch CVE info from NVD API (v2.0)
def fetch_cve_data(cve_id):
    API_KEY = 'fbcb6fee-ef22-4e0a-b5cb-b87df08d7fd1'.strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": API_KEY}

    try:
        
        proxies = {
          "http": "http://rb-proxy-in.bosch.com:8080",
         "https": "http://rb-proxy-in.bosch.com:8080"
        }
        #proxies = {"https": "http://rb-proxy-in.bosch.com:8080"}
        response = requests.get(url, headers=headers, proxies=proxies)
       # response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# Extract CVSS data, regardless of version (v2, v3.0, v3.1)
def extract_cvss(metrics):
    for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if key in metrics:
            return metrics[key][0].get('cvssData', {})
    return {}

# Generate prompt from CVE data
def format_cve_prompt(cve_id, cve_data):
    try:
        item = cve_data['vulnerabilities'][0]['cve']
        desc = item['descriptions'][0]['value']
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


# Main function to analyze CVE using LLM
def analyze_cve(cve_id):
    cve_data = fetch_cve_data(cve_id)
    if "error" in cve_data:
        return f"❌ Failed to retrieve CVE: {cve_data['error']}"

    prompt = format_cve_prompt(cve_id, cve_data)
    if prompt.startswith("Error"):
        return prompt

    return queryLLM(prompt)



# Fetch CVE details using NVD API v2.0
def fetch_cve_details_v2(cve_id, api_key):
    url = f"https://api.nvd.nist.gov/vuln/v2/cve/{cve_id}"
    headers = {
        "apiKey": api_key,
        "Content-Type": "application/json"
    }

    response = requests.get("https://api.nvd.nist.gov/vuln/v2/cve/CVE-2023-0464", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch CVE details: {response.status_code} - {response.text}")

# Parse data and generate recommendation
def parse_cve_data_v2(cve_data):
    try:
        vuln = cve_data.get("vulnerability", {})
        cve_id = vuln.get("cve", {}).get("id", "N/A")
        source_desc = vuln.get("descriptions", [{}])[0].get("value", "No description")
        published = vuln.get("published", "N/A")

        cvss_data = vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        score = cvss_data.get("baseScore", "N/A")
        severity = cvss_data.get("baseSeverity", "N/A")

        if isinstance(score, (float, int)):
            if score >= 9.0:
                recommendation = "Critical — patch immediately."
            elif score >= 7.0:
                recommendation = "High — apply patch quickly."
            elif score >= 4.0:
                recommendation = "Medium — plan to patch."
            else:
                recommendation = "Low — monitor and patch regularly."
        else:
            recommendation = "Score not available — assess manually."

        return {
            "CVE ID": cve_id,
            "Description": source_desc,
            "Published Date": published,
            "CVSS Score": score,
            "Severity": severity,
            "Recommendation": recommendation
        }

    except Exception as e:
        raise Exception(f"Error parsing v2 CVE data: {e}")

# Export to JSON and Excel
def export_results(result_dict, json_file, excel_file):
    with open(json_file, 'w') as jf:
        json.dump(result_dict, jf, indent=4)

    df = pd.DataFrame([result_dict])
    df.to_excel(excel_file, index=False)
    


# Run the analysis
if __name__ == "__main__":
    cve_id = "CVE-2023-0464"
    llmResponse = analyze_cve(cve_id)
    
    api_key = "e3b62450ed794963896276597b8bd87a"
    
    try:
        cve_data = fetch_cve_details_v2(cve_id, api_key)
        result = parse_cve_data_v2(cve_data)
        export_results(result, "results.json", "results.xlsx")
        print("✅ Export completed: results.json and results.xlsx")
    except Exception as e:
        print(f"❌ Error: {e}")
