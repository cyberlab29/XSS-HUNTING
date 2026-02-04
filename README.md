# 🎯 XSS Hunting (NEON_VOID)
**XSS Hunting** XSS Hunting is an automated Cross-Site Scripting (XSS) reconnaissance and testing tool built in Python for learning and security research.  
It follows a staged payload execution model to improve scan speed, reduce noise, and minimize false positives.

---

## 🏗️ Architecture

The tool follows a sophisticated multi-stage pipeline to ensure thorough coverage while maintaining speed.

1.  **Reconnaissance & Asset Discovery**:
    *   Aggregates subdomains using `subfinder`.
    *   Harvests URLs from web archives via `GAU` and `Waybackurls`.
    *   Finds live hosts and endpoints using `HTTPX`.
2.  **Parameter Mining & Injection Validation**:
    *   Extracts parameters using `ParamSpider` and `Arjun`.
    *   Runs initial **Reflection Checks** to identify inputs that echo back in the HTTP response.
    *   Performs **Context Discovery** to determine if the input lands in HTML, Attribute, JS, or Comment contexts.
3.  **Deep Payload Testing**:
    *   Executes a targeted fuzzing engine using context-aware payloads.
    *   Validates successful execution (e.g., matching character encoding and escape sequences).

---

## ✨ Features

*   **Concurrent Execution**: Leverages Python's `concurrent.futures` for high-speed scanning.
*   **3-Stage Fuzzing**: Reduces noise by only testing reflecting parameters with contextually relevant payloads.
*   **Beautiful CLI**: Real-time progress tracking, live activity logs, and formatted results using the `Rich` library.
*   **WAF Detection**: Automatically adjusts scan intensity if a Web Application Firewall is detected.
*   **Modular Design**: Easily add custom payload lists or integrate new discovery modules.

---

## 🛠️ Installation

### Prerequisites

Ensure you have **Python 3.x** and **Go** installed on your system.

### Steps

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/xss-hunting-tool.git
    cd xss-hunting-tool
    ```

2.  **Install Python Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install External Requirements**:
    The tool includes a built-in automated installer for all dependencies:
    *   Launch the tool: `python3 main.py`
    *   Press **`I`** to enter the **SYSTEM_SETUP** menu.
    *   The tool will automatically deploy: **ParamSpider**, **Gau**, **HTTPX**, **Subfinder**, and more.

---

## 🚀 Usage

Launch a full-automated hunt against a target domain:

```bash
python3 main.py -t target.com
```

### Options
*   `-t`, `--target`: Specify the target domain (e.g., `example.com`).
*   `-p`, `--payloads`: Path to a custom payloads file (JSON or TXT).

---

## 🔍 Requirements

| Tool | Purpose |
| :--- | :--- |
| **Subfinder** | Cloud-based subdomain discovery. |
| **HTTPX** | Fast and multi-purpose HTTP toolkit for host verification. |
| **GAU / Waybackurls** | Fetching historical URLs from AlienVault, Wayback Machine, etc. |
| **ParamSpider** | Special mining for parameter-heavy URLs. |
| **Arjun** | Discovery of hidden GET/POST parameters. |

---

## ⚠️ Educational Use Disclaimer

This tool is designed for **educational purposes** and **authorized security testing** only. Attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
##License

MIT License 

**Created by RASHI** 
 *Powering the next generation of automated web security.*
