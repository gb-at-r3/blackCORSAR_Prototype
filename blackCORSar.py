import xml.etree.ElementTree as ET
import base64
import json
import argparse
import datetime
import os

# Function to decode Base64 HTTP responses
def decode_response(base64_data):
    try:
        decoded_bytes = base64.b64decode(base64_data)
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded_text
    except Exception:
        return None

# Function to analyze HTTP headers and detect compliance issues
def analyze_headers(headers):
    compliance = {
        "CORS": {
            "CORS too open": {"tooOpen": False, "issue": ""},
            "Allow Credentials Enabled": {"isRisky": False, "scenario": "Allows credentials sharing across origins"}
        },
        "Security Headers": {
            "No Strict-Transport-Security": {"isVuln": False, "scenario": "Exposes to downgrade attack"},
            "X-Frame-Options Missing": {"isVuln": False, "scenario": "Vulnerable to clickjacking"},
            "X-Content-Type-Options Missing": {"isVuln": False, "scenario": "MIME sniffing risk"},
            "Referrer-Policy Missing": {"isVuln": False, "scenario": "Potential information leakage"},
            "Permissions-Policy Missing": {"isVuln": False, "scenario": "Browser features might be abused"}
        },
        "CSRF Protection": {
            "SameSite Cookie Missing": {"isVuln": False, "scenario": "Potential CSRF attack"},
            "Secure Cookie Missing": {"isVuln": False, "scenario": "Exposed to HTTP interception"}
        },
        "CSP": {
            "No CSP Header": {"isVuln": False, "scenario": "XSS not mitigated"},
            "Unsafe Inline Scripts": {"isVuln": False, "scenario": "Potential execution of malicious scripts"}
        }
    }
    
    for header in headers:
        lower_header = header.lower()
        
        if lower_header.startswith("access-control-allow-origin"):
            if "*" in lower_header:
                compliance["CORS"]["CORS too open"]["tooOpen"] = True
                compliance["CORS"]["CORS too open"]["issue"] = header
        if lower_header.startswith("access-control-allow-credentials") and "true" in lower_header:
            compliance["CORS"]["Allow Credentials Enabled"]["isRisky"] = True
        
        if "strict-transport-security" not in lower_header:
            compliance["Security Headers"]["No Strict-Transport-Security"]["isVuln"] = True
        if "x-frame-options" not in lower_header:
            compliance["Security Headers"]["X-Frame-Options Missing"]["isVuln"] = True
        if "x-content-type-options" not in lower_header:
            compliance["Security Headers"]["X-Content-Type-Options Missing"]["isVuln"] = True
        if "referrer-policy" not in lower_header:
            compliance["Security Headers"]["Referrer-Policy Missing"]["isVuln"] = True
        if "permissions-policy" not in lower_header:
            compliance["Security Headers"]["Permissions-Policy Missing"]["isVuln"] = True
        
        if lower_header.startswith("set-cookie"):
            if "samesite=" not in lower_header:
                compliance["CSRF Protection"]["SameSite Cookie Missing"]["isVuln"] = True
            if "secure" not in lower_header:
                compliance["CSRF Protection"]["Secure Cookie Missing"]["isVuln"] = True
        
        if lower_header.startswith("content-security-policy"):
            compliance["CSP"]["No CSP Header"]["isVuln"] = False
            if "unsafe-inline" in lower_header:
                compliance["CSP"]["Unsafe Inline Scripts"]["isVuln"] = True
        else:
            compliance["CSP"]["No CSP Header"]["isVuln"] = True
    
    return compliance

# Function to parse the XML file and analyze compliance
def parse_burp_xml(file_path):
    try:
        tree = ET.parse(file_path)
    except ET.ParseError:
        print("[ERROR] The XML file appears to be corrupted. Are you still sniffing glue?")
        exit(1)
    
    root = tree.getroot()
    results = []
    
    for item in root:
        url = item.find("url").text if item.find("url") is not None else "Unknown"
        response_base64 = item.find("response").text if item.find("response") is not None else ""
        
        if response_base64:
            decoded_response = decode_response(response_base64)
            if decoded_response:
                headers = decoded_response.split("\n")[:20]  # Limit to first 20 headers
                compliance = analyze_headers(headers)
                results.append({"url": url, "compliance": compliance, "headers": headers})
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BlackCORSar - Web Security Compliance Analyzer")
    parser.add_argument("--input", required=True, help="Path to the Burp XML export file")
    parser.add_argument("--output", choices=["json", "xml", "html"], default="json", help="Output format")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed explanations in the output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print("[ERROR] Input file not found! Maybe you need an IV drip of coffee?")
        exit(1)
    
    results = parse_burp_xml(args.input)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"blackcorsar_{timestamp}.{args.output}"
    
    with open(output_filename, "w") as f:
        if args.output == "json":
            json.dump(results, f, indent=4)
    
    print(f"Report generated: {output_filename}")
