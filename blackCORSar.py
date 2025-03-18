import xml.etree.ElementTree as ET
import base64
import json
import argparse
import datetime
import os
import sys

# Function to decode Base64 HTTP responses
def decode_response(base64_data):
    try:
        decoded_bytes = base64.b64decode(base64_data)
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded_text
    except Exception:
        return None

# Risk descriptions for compliance checks
RISK_DESCRIPTIONS = {
    "CORS": {
        "CORS too open": "Allows any origin to access resources, leading to potential data exfiltration."
    },
    "Security Headers": {
        "No Strict-Transport-Security": "Exposes the site to downgrade attacks and man-in-the-middle attacks.",
        "X-Frame-Options Missing": "Makes the site vulnerable to clickjacking attacks."
    },
    "CSRF Protection": {
        "SameSite Cookie Missing": "Allows cross-site request forgery attacks, letting attackers perform actions on behalf of users."
    },
    "CSP": {
        "No CSP Header": "Lack of a Content Security Policy increases the risk of cross-site scripting (XSS) attacks."
    }
}

# Function to analyze HTTP headers and detect compliance issues
def analyze_headers(headers, compliance_checks):
    compliance = {
        "CORS": {"CORS too open": {"is_vulnerable": False, "Risk": ""}},
        "Security Headers": {
            "No Strict-Transport-Security": {"is_vulnerable": False, "Risk": ""},
            "X-Frame-Options Missing": {"is_vulnerable": False, "Risk": ""}
        },
        "CSRF Protection": {"SameSite Cookie Missing": {"is_vulnerable": False, "Risk": ""}},
        "CSP": {"No CSP Header": {"is_vulnerable": False, "Risk": ""}}
    }
    
    for header in headers:
        lower_header = header.lower()
        
        if "CORS" in compliance_checks and "access-control-allow-origin" in lower_header:
            if "*" in lower_header:
                compliance["CORS"]["CORS too open"]["is_vulnerable"] = True
                compliance["CORS"]["CORS too open"]["Risk"] = RISK_DESCRIPTIONS["CORS"]["CORS too open"]
        
        if "Security Headers" in compliance_checks and "strict-transport-security" not in lower_header:
            compliance["Security Headers"]["No Strict-Transport-Security"]["is_vulnerable"] = True
            compliance["Security Headers"]["No Strict-Transport-Security"]["Risk"] = RISK_DESCRIPTIONS["Security Headers"]["No Strict-Transport-Security"]
        
        if "Security Headers" in compliance_checks and "x-frame-options" not in lower_header:
            compliance["Security Headers"]["X-Frame-Options Missing"]["is_vulnerable"] = True
            compliance["Security Headers"]["X-Frame-Options Missing"]["Risk"] = RISK_DESCRIPTIONS["Security Headers"]["X-Frame-Options Missing"]
        
        if "CSRF Protection" in compliance_checks and "set-cookie" in lower_header:
            if "samesite=" not in lower_header:
                compliance["CSRF Protection"]["SameSite Cookie Missing"]["is_vulnerable"] = True
                compliance["CSRF Protection"]["SameSite Cookie Missing"]["Risk"] = RISK_DESCRIPTIONS["CSRF Protection"]["SameSite Cookie Missing"]
        
        if "CSP" in compliance_checks and "content-security-policy" not in lower_header:
            compliance["CSP"]["No CSP Header"]["is_vulnerable"] = True
            compliance["CSP"]["No CSP Header"]["Risk"] = RISK_DESCRIPTIONS["CSP"]["No CSP Header"]
        
    return {key: compliance[key] for key in compliance_checks if key in compliance}

# Function to parse the XML file and analyze compliance
def parse_burp_xml(file_path, compliance_checks, verbose=False):
    try:
        tree = ET.parse(file_path)
    except ET.ParseError:
        print("[ERROR] The XML file appears to be corrupted. Exiting.")
        sys.exit(1)
    
    root = tree.getroot()
    results = []
    
    for item in root:
        url = item.find("url").text if item.find("url") is not None else "Unknown"
        response_base64 = item.find("response").text if item.find("response") is not None else ""
        
        decoded_response = decode_response(response_base64) if response_base64 else "N/A"
        headers = decoded_response.split("\n\n")[0].split("\n") if decoded_response else []
        compliance = analyze_headers(headers, compliance_checks)
        
        result = {"url": url, "compliance": compliance}
        if verbose:
            result["response_headers"] = headers
        
        results.append(result)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BlackCORSar - Web Security Compliance Analyzer")
    parser.add_argument("--input", required=True, help="Path to the Burp XML export file")
    parser.add_argument("--compliance", required=True, help="Comma-separated compliance checks: CORS,CSP,securityHeader,CSRF,all")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed output (includes headers in JSON mode)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print("[ERROR] Input file not found!")
        sys.exit(1)
    
    compliance_checks = args.compliance.split(",")
    if "all" in compliance_checks:
        compliance_checks = ["CORS", "Security Headers", "CSRF Protection", "CSP"]
    
    results = parse_burp_xml(args.input, compliance_checks, args.verbose)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"blackcorsar_{timestamp}.json"
    
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    
    print(f"Report generated: {output_filename}")

