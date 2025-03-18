import json
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Generate an HTML security report from BlackCORSar JSON output.")
parser.add_argument("--input", required=True, help="Path to the JSON report file")
parser.add_argument("--output", required=True, help="Path to save the generated HTML report")
args = parser.parse_args()

# Load the JSON file
file_path = args.input
with open(file_path, "r") as file:
    data = json.load(file)

# Define risk descriptions for each issue with more details
risk_descriptions = {
    "CORS too open": (
        "An overly permissive CORS configuration allows any origin to access the application's resources. "
        "This can lead to data leakage, unauthorized API calls, and potential session hijacking. "
        "Attackers can exploit this weakness to steal sensitive information by embedding malicious scripts in another domain."
    ),
    "No Strict-Transport-Security": (
        "The absence of HTTP Strict Transport Security (HSTS) makes the application vulnerable to downgrade attacks. "
        "Attackers can perform man-in-the-middle (MITM) attacks by forcing users to connect over HTTP instead of HTTPS, "
        "potentially intercepting and modifying traffic, leading to credential theft and session hijacking."
    ),
    "X-Frame-Options Missing": (
        "Without the X-Frame-Options header, the application is vulnerable to clickjacking attacks. "
        "Malicious actors can embed the site within an invisible iframe and trick users into performing unintended actions. "
        "This can lead to unauthorized transactions, changes in security settings, or exposure of sensitive information."
    ),
    "SameSite Cookie Missing": (
        "Lack of the SameSite attribute on cookies makes the application susceptible to Cross-Site Request Forgery (CSRF) attacks. "
        "Attackers can exploit an authenticated user's session by tricking them into making unintended requests to the application. "
        "This can result in unauthorized actions being performed on behalf of the victim, such as fund transfers or password changes."
    ),
    "No CSP Header": (
        "Without a Content Security Policy (CSP), the application is at a higher risk of Cross-Site Scripting (XSS) attacks. "
        "Malicious scripts can be injected into web pages, leading to session hijacking, data theft, and unauthorized actions. "
        "CSP mitigates these threats by restricting the sources from which scripts can be loaded, thereby reducing the attack surface."
    )
}

# Start HTML generation
html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h2>Security Risk Overview</h2>
"""

# Insert risk descriptions in the report
for issue, description in risk_descriptions.items():
    html_content += f"<p><b>{issue}:</b> {description}</p>"

# Start the results table
html_content += """
    <h2>Security Compliance Table</h2>
    <table>
        <tr>
            <th>URL</th>
            <th>CORS</th>
            <th>Security Headers</th>
            <th>CSRF</th>
            <th>CSP</th>
        </tr>
"""

# Populate the table with compliance results
for entry in data:
    url = entry["url"]
    compliance = entry["compliance"]
    
    cors_status = compliance["CORS"]["CORS too open"]["is_vulnerable"]
    sec_headers_status = any(details["is_vulnerable"] for details in compliance["Security Headers"].values())
    csrf_status = compliance["CSRF Protection"]["SameSite Cookie Missing"]["is_vulnerable"]
    csp_status = compliance["CSP"]["No CSP Header"]["is_vulnerable"]
    
    html_content += f"""
        <tr>
            <td>{url}</td>
            <td>{'true' if cors_status else 'false'}</td>
            <td>{'true' if sec_headers_status else 'false'}</td>
            <td>{'true' if csrf_status else 'false'}</td>
            <td>{'true' if csp_status else 'false'}</td>
        </tr>
    """

# Close the table and finish the HTML file
html_content += """
    </table>
</body>
</html>
"""

# Write the HTML report to a file
output_path = args.output
with open(output_path, "w") as file:
    file.write(html_content)

print(f"Report generated: {output_path}")

