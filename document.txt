1. LLM Integration via Azure OpenAI
Purpose: Queries the GPT-4o-mini model deployed on Azure.

Function: queryLLM(promptQuery)

Use case: Automatically generates a high-level security analysis of a CVE using its description and CVSS score.

🌐 2. Fetching CVE Data from NVD API
Function: fetch_cve_data_and_save(cve_id)

Purpose: Retrieves CVE metadata from NVD (National Vulnerability Database) using their REST API.

Output: Saves the fetched data into a local JSON file named {cve_id}.json.

📊 3. Extracting CVSS (Base) Score
Function: extract_base_score_from_json(filename)

Purpose: Loads saved JSON, extracts the baseScore from one of the supported CVSS versions (v3.1, v3.0, or v2).

Output: Returns a float (e.g., 7.5) representing the severity of the vulnerability.

📝 4. Prompt Creation for LLM
Function: format_cve_prompt(cve_id, cve_data)

Purpose: Generates a well-structured prompt including:

CVE ID

Vulnerability description

CVSS base score

Severity level

Why: Helps the LLM provide a focused, actionable analysis.

📈 5. Business Context Weighting System
Functions:

calculate_modifier(args)

read_input_and_calculate(cvss_base)

User Inputs (via command-line arguments):

Confidentiality Requirement (--cr)

Integrity Requirement (--ir)

Availability Requirement (--ar)

Data Sensitivity

HSM Usage

External Trust Anchors

Financial Risk

Scoring logic:

Each input is weighted: High = 3, Medium = 2, Low = 1

Total scores are mapped to modifiers:

18 → 1.5

14–17 → 1.3

10–13 → 1.2

<10 → 1.0

Adjusted Score: adjusted_score = base_score * modifier

🚀 6. Main Program Execution
Retrieves CVE data.

Extracts CVSS base score.

Runs LLM-based CVE analysis.

Accepts user-provided business risk parameters via CLI.

Outputs the adjusted CVSS score, which reflects technical severity + business impact.

🛡️ Overall Purpose:
This tool is built to automate the analysis and contextual prioritization of vulnerabilities, combining:

Official severity (from NVD),

Generative AI insights (via LLM),

Internal business risk factors.

Let me know if you want a diagram or flowchart to go with this!