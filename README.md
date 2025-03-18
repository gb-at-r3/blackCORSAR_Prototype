# blackCORSar_PROTO - Web Page Security Checker 🏴‍☠️

## 📌 Overview

BlackCORSar is a CLI tool designed to analyze web security compliance from Burp Suite XML exports. It evaluates HTTP headers based on four core pillars:

* CORS (Cross-Origin Resource Sharing)

* Security Headers (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)

* CSRF Protections (Secure and SameSite cookie policies)

* Content Security Policy (CSP)

It helps identify misconfigurations, vulnerabilities, and security risks in web applications.

## 🚀 Features

✅ Parses Burp Suite XML exports
✅ Checks compliance for CORS, Security Headers, CSRF, CSP
✅ Customizable compliance checks with `--compliance`
✅ JSON, XML, and HTML output formats
✅ Verbose mode for in-depth explanations
✅ Smart error handling with humor 😆

## 🔧 Installation

BlackCORSar is currently a Python prototype before moving to Rust.

### Clone the repository
```
git clone https://github.com/yourusername/blackcorsar.git

cd blackcorsar
```

### Install dependencies
`pip install -r requirements.txt`

## 🏴‍☠️ Usage

### Basic Scan

`python blackcorsar.py --input=burp.xml --compliance=all --output=json`

### Custom Compliance Checks

### Analyze only CORS and CSP:

`python blackcorsar.py --input=burp.xml --compliance=CORS,CSP --output=xml`

### Enable Verbose Mode

Get detailed explanations:

`python blackcorsar.py --input=burp.xml --compliance=all --output=html --verbose`

## ⚠️ Error Handling

| Error | Message |
|-------|---------|
|No `--input` file| [ERROR] No input file! Maybe you need an IV drip of coffee? ☕|
|XML is corrupted| [ERROR] The XML file appears to be corrupted. Are you still sniffing glue? 😵|
|No output file name provided| A timestamp-based filename is generated automatically.|

## 🔥 Roadmap

* Enhance Python prototype based on user feedback ✅
* Port to Rust for better performance 🦀
* Expand compliance checks (e.g., security.txt validation, HTTPS enforcement)
* Implement HTML reporting with styling 🎨

## 🤝 Contributing

Pull requests, feature requests, and bug reports are welcome! If you want to contribute:

* Fork the repo
* Create a new branch
* Commit your changes
* Open a PR!

## ⚖️ License

MIT License. Free to use, modify, and distribute.

🎯 BlackCORSar: Because web security should be fun, effective, and slightly sarcastic. 🏴‍☠️
