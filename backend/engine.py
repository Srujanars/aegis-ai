"""
AegisAI - Sanitization & Reversible De-Tokenization Core Engine
Zero external dependencies (Pure Python 3 standard library: re, json, hashlib)
"""

import re
import uuid

# Threat Definitions with Regex & Heuristics
PATTERNS = {
    "AWS_ACCESS_KEY": {
        "regex": r"\b(AKIA[0-9A-Z]{16})\b",
        "category": "Cloud Credentials",
        "severity": "CRITICAL",
        "label": "AWS Access Key ID"
    },
    "AWS_SECRET_KEY": {
        "regex": r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)[\s=:\"]+([A-Za-z0-9/+=]{40})",
        "category": "Cloud Credentials",
        "severity": "CRITICAL",
        "label": "AWS Secret Access Key",
        "group": 1
    },
    "OPENAI_KEY": {
        "regex": r"\b(sk-[a-zA-Z0-9_-]{20,64})\b",
        "category": "API Tokens",
        "severity": "CRITICAL",
        "label": "OpenAI / LLM API Key"
    },
    "GITHUB_TOKEN": {
        "regex": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b",
        "category": "API Tokens",
        "severity": "HIGH",
        "label": "GitHub Personal Access Token"
    },
    "PRIVATE_KEY": {
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "category": "Cryptographic Keys",
        "severity": "CRITICAL",
        "label": "Private RSA / SSH Key"
    },
    "DB_CONNECTION_URI": {
        "regex": r"(?i)\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|oracle):\/\/)([^:\s\/]+):([^@\s\/]+)@([^\s\/:]+)(?::(\d+))?(\/[^\s\?\"']*)?",
        "category": "Database Secrets",
        "severity": "CRITICAL",
        "label": "Database Connection String with Password",
        "is_db_uri": True
    },
    "PAN_CARD": {
        "regex": r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b",
        "category": "Financial / PII",
        "severity": "HIGH",
        "label": "Indian PAN Number (DPDP Act Violation)"
    },
    "AADHAAR_NUMBER": {
        "regex": r"\b([2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b",
        "category": "Financial / PII",
        "severity": "CRITICAL",
        "label": "Indian Aadhaar ID (DPDP Act Violation)"
    },
    "CREDIT_CARD": {
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "category": "Financial / PII",
        "severity": "CRITICAL",
        "label": "Credit Card Number (PCI-DSS)"
    },
    "INTERNAL_HOST": {
        "regex": r"\b([a-zA-Z0-9-]+\.(?:internal|corp|local|lan|vpc|cluster\.local))\b",
        "category": "Internal Infrastructure",
        "severity": "MEDIUM",
        "label": "Internal Corporate Domain"
    },
    "INTERNAL_IP": {
        "regex": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b",
        "category": "Internal Infrastructure",
        "severity": "MEDIUM",
        "label": "Private RFC-1918 IP Address"
    },
    "EMAIL_ADDRESS": {
        "regex": r"\b([a-zA-Z0-9._%+-]+@(?!example\.com|company\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
        "category": "Personal Data (PII)",
        "severity": "LOW",
        "label": "User Email Address"
    }
}

class AegisGuard:
    def __init__(self):
        # In-memory mapping vault: maps synthetic token -> real secret
        # Keyed by session_id to isolate requests
        self.session_vaults = {}

    def sanitize(self, raw_prompt, session_id=None):
        """
        Scans raw prompt, replaces sensitive entities with synthetic tokens,
        and saves reverse mappings in memory.
        """
        if not session_id:
            session_id = str(uuid.uuid4())[:8]

        vault = {}
        intercepted_items = []
        sanitized_text = raw_prompt

        counter = {}

        # 1. First Pass: Handle Complex DB Connection Strings
        db_config = PATTERNS["DB_CONNECTION_URI"]
        for match in re.finditer(db_config["regex"], sanitized_text):
            full_uri = match.group(0)
            proto = match.group(1)
            user = match.group(2)
            pwd = match.group(3)
            host = match.group(4)
            port = match.group(5) or ""
            db_name = match.group(6) or ""

            synth_user = "<SYNTH_DB_USER_1>"
            synth_pwd = "<SYNTH_DB_PASS_1>"
            synth_host = "<SYNTH_DB_HOST_1>"

            vault[synth_user] = user
            vault[synth_pwd] = pwd
            vault[synth_host] = host

            synth_uri = f"{proto}{synth_user}:{synth_pwd}@{synth_host}{':' + port if port else ''}{db_name}"
            sanitized_text = sanitized_text.replace(full_uri, synth_uri)

            intercepted_items.append({
                "type": db_config["label"],
                "category": db_config["category"],
                "severity": db_config["severity"],
                "masked_tokens": [synth_user, synth_pwd, synth_host]
            })

        # 2. Second Pass: All Other Threat Patterns
        for key, config in PATTERNS.items():
            if config.get("is_db_uri"):
                continue

            pattern = config["regex"]
            group_idx = config.get("group", 1)

            for match in re.finditer(pattern, sanitized_text):
                try:
                    val = match.group(group_idx)
                except IndexError:
                    val = match.group(0)

                if val in vault.values():
                    continue

                c_idx = counter.get(key, 0) + 1
                counter[key] = c_idx
                synth_token = f"<SYNTH_{key}_{c_idx}>"

                vault[synth_token] = val
                sanitized_text = sanitized_text.replace(val, synth_token)

                intercepted_items.append({
                    "type": config["label"],
                    "category": config["category"],
                    "severity": config["severity"],
                    "masked_token": synth_token
                })

        self.session_vaults[session_id] = vault

        return {
            "session_id": session_id,
            "raw_prompt": raw_prompt,
            "sanitized_prompt": sanitized_text,
            "intercepted_count": len(intercepted_items),
            "threats_detected": intercepted_items,
            "vault_size": len(vault)
        }

    def detokenize(self, ai_response_text, session_id):
        """
        Restores original secrets locally into the response returned by AI.
        """
        vault = self.session_vaults.get(session_id, {})
        rehydrated_text = ai_response_text

        # Replace all synthetic tokens with the real local values
        for synth_token, real_secret in vault.items():
            rehydrated_text = rehydrated_text.replace(synth_token, real_secret)

        return rehydrated_text

    def simulate_ai_response(self, sanitized_prompt):
        """
        Simulates an intelligent AI (e.g., ChatGPT / Claude / DeepSeek)
        answering the prompt using the synthetic tokens.
        """
        if "<SYNTH_DB_PASS_1>" in sanitized_prompt or "<SYNTH_DB_HOST_1>" in sanitized_prompt:
            return (
                "```python\n"
                "# AegisAI Safe Execution: Refactored database query\n"
                "import psycopg2\n\n"
                "def connect_database():\n"
                "    conn = psycopg2.connect(\n"
                "        dbname='users',\n"
                "        user='<SYNTH_DB_USER_1>',\n"
                "        password='<SYNTH_DB_PASS_1>',\n"
                "        host='<SYNTH_DB_HOST_1>',\n"
                "        port=5432\n"
                "    )\n"
                "    print('Connected securely using connection pooling.')\n"
                "    return conn\n"
                "```"
            )
        elif "<SYNTH_AWS_ACCESS_KEY_1>" in sanitized_prompt:
            return (
                "```python\n"
                "# Refactored S3 File Uploader using Boto3\n"
                "import boto3\n\n"
                "s3_client = boto3.client(\n"
                "    's3',\n"
                "    aws_access_key_id='<SYNTH_AWS_ACCESS_KEY_1>',\n"
                "    region_name='ap-south-1'\n"
                ")\n"
                "# Added proper retry logic and bucket validation\n"
                "def upload_report(bucket_name, file_path):\n"
                "    s3_client.upload_file(file_path, bucket_name, 'exports/' + file_path)\n"
                "    print('Upload succeeded with verified IAM scope.')\n"
                "```"
            )
        elif "<SYNTH_PAN_CARD_1>" in sanitized_prompt or "<SYNTH_AADHAAR_NUMBER_1>" in sanitized_prompt:
            return (
                "```python\n"
                "# Cleaned Customer Data Pipeline complying with DPDP regulations\n"
                "import hashlib\n\n"
                "customer_record = {\n"
                "    'national_id': '<SYNTH_PAN_CARD_1>',\n"
                "    'id_status': 'VERIFIED',\n"
                "    'sha256_hash': hashlib.sha256('<SYNTH_PAN_CARD_1>'.encode()).hexdigest()\n"
                "}\n"
                "# Storing pseudonymized hash instead of raw identity\n"
                "print('Indexed customer safely: ' + customer_record['sha256_hash'])\n"
                "```"
            )
        else:
            return (
                "Here is the optimized solution for your code:\n\n"
                "```python\n"
                "# AI Code Refactoring & Security Fix\n"
                "def execute_task():\n"
                "    # Processed safely without data leaks\n"
                "    return {'status': 'success', 'data_cleansed': True}\n"
                "```"
            )

if __name__ == "__main__":
    guard = AegisGuard()
    test_code = 'db = "postgres://root:SuperSecretPass999@db.prod.internal:5432/crm" for user PAN ABCDE1234F'
    print("Testing AegisGuard...")
    result = guard.sanitize(test_code)
    print("Raw:       ", result["raw_prompt"])
    print("Sanitized: ", result["sanitized_prompt"])
    print("Threats:   ", len(result["threats_detected"]))
    
    ai_raw_out = guard.simulate_ai_response(result["sanitized_prompt"])
    print("\nAI Sees:   ", ai_raw_out[:100], "...")
    rehydrated = guard.detokenize(ai_raw_out, result["session_id"])
    print("\nRehydrated:", rehydrated[:100], "...")
    assert "SuperSecretPass999" in rehydrated
    print("\n✓ Verification passed with 100% fidelity!")
