import argparse
from openai import OpenAI

llmClient = OpenAI(
    api_key="dummy",  # Overwritten by API manager
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={"genaiplatform-farm-subscription-key": "40ed81f7152040b7ac724ad59379849b"}
)

# Query LLM with a given prompt
def get_business_modifier(promptQuery, model_name="gpt-4o-mini"):
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

# Create LLM client using custom Azure OpenAI endpoint

# Define the weight mapping
WEIGHTS = {
    "high": 3,
    "medium": 2,
    "low": 1
}

def get_weight(value):
    return WEIGHTS.get(value.lower(), 1)  # default to 1 if invalid

def calculate_modifier(args):
    scores = [
        get_weight(args.cr),
        get_weight(args.ir),
        get_weight(args.ar),
        get_weight(args.data_sensitivity),
        get_weight(args.hsm_usage),
        get_weight(args.external_trust),
        get_weight(args.financial_risk),
    ]
    total_score = sum(scores)

    # Rule-based modifier mapping
    if total_score == 18:
        modifier = 1.5
    elif total_score >= 14:
        modifier = 1.3
    elif total_score >= 10:
        modifier = 1.2
    else:
        modifier = 1.0

    return modifier, total_score

def main():
    parser = argparse.ArgumentParser(description="Calculate Adjusted CVSS Score with Business Context")
    parser.add_argument("--cvss_base", type=float, required=True)
    parser.add_argument("--cr", type=str, required=True)
    parser.add_argument("--ir", type=str, required=True)
    parser.add_argument("--ar", type=str, required=True)
    parser.add_argument("--data_sensitivity", type=str, required=True)
    parser.add_argument("--hsm_usage", type=str, required=True)
    parser.add_argument("--external_trust", type=str, required=True)
    parser.add_argument("--financial_risk", type=str, required=True)

    args = parser.parse_args()

    prompt = f"""
A vulnerability has a base CVSS score of {args.cvss_base}.
Business context:
- Confidentiality Requirement: {args.cr}
- Integrity Requirement: {args.ir}
- Availability Requirement: {args.ar}
- Data Sensitivity: {args.data_sensitivity}
- HSM Usage: {args.hsm_usage}
- External Trust Anchors: {args.external_trust}
- Financial Risk: {args.financial_risk}

Based on these, suggest a numeric 'Business Modifier' (1.0 to 2.0 scale) that adjusts the base score to reflect business impact only.
Respond with only the number.
"""

   # modifier = get_business_modifier(prompt)
    modifier, total_score = calculate_modifier(args)
    adjusted_score = round(args.cvss_base * modifier, 1)

    print(f"Total Score: {total_score}")
    print(f"Business Modifier (Rule-Based): {modifier}")
    print(f"Adjusted CVSS Score: {adjusted_score}")

if __name__ == "__main__":
    main()
