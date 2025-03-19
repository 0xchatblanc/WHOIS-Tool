# WHOIS Tool 🕵️‍♂️

**WHOIS Tool** is a highly advanced asynchronous Python-based tool designed for performing efficient WHOIS lookups. It incorporates modern Python features such as dataclasses, caching, and multi-threading via a thread pool for enhanced performance and scalability.

---

## ✨ Features

- 🔍 **WHOIS Lookup**:

  - Retrieve registrar information, WHOIS servers, creation dates, expiration dates, and DNS details.
  - Identify domain statuses and associated emails (if available).
  - Supports asynchronous operations for rapid concurrent lookups.

- 💾 **Export Options**:

  - Export results to JSON or CSV for structured data analysis and sharing.

- ⚡ **Performance Optimizations**:

  - Leverages caching (`lru_cache`) for repeated lookups.
  - Uses Python's `asyncio` and a thread pool executor for concurrent operations.

- 🖥️ **User-Friendly CLI**:

  - Intuitive menu with color-coded outputs for readability and better UX.

---

## 🚀 Installation

### Prerequisites

Ensure you have **Python 3.7** or a newer version installed on your system.

### Install Dependencies

Run the following command to install the required Python modules:

```bash
pip install python-whois colorama
```

---

## ⚙️ Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/0xchatblanc/whois-tool.git
   cd whois-tool
   ```

2. Run the tool:

   ```bash
   python whois_tool.py
   ```

3. Follow the on-screen menu to perform WHOIS lookups and export results.

---

## 🛠️ Example Workflow

1. Select **1** from the menu to perform a WHOIS lookup.
2. Enter the domain name (e.g., `example.com`).
3. View the results displayed in the terminal.
4. Use options **2** or **3** to export results to JSON or CSV.

---

## 📋 Example Output

### CLI Output

```
╔═══════════════╗
║ WHOIS Results ║
╚═══════════════╝
Domain             : example.com
Registrar          : Example Registrar
Whois Server       : whois.example.com
Creation Date      : 1995-08-13
Expiration Date    : 2025-08-13
Last Updated       : 2022-01-01
Status             : active
Name Servers       : ns1.example.com, ns2.example.com
Emails             : contact@example.com
```

### JSON Export

```json
[
    {
        "domain": "example.com",
        "registrar": "Example Registrar",
        "whois_server": "whois.example.com",
        "creation_date": "1995-08-13",
        "expiration_date": "2025-08-13",
        "updated_date": "2022-01-01",
        "status": "active",
        "name_servers": "ns1.example.com, ns2.example.com",
        "emails": "contact@example.com"
    }
]
```

### CSV Export

```
domain,registrar,whois_server,creation_date,expiration_date,updated_date,status,name_servers,emails
example.com,Example Registrar,whois.example.com,1995-08-13,2025-08-13,2022-01-01,active,"ns1.example.com, ns2.example.com",contact@example.com
```

---

## 🗂️ Project Structure

```
whois-tool/
├── whois_tool.py           # Main script
└── README.md               # Documentation
```

---

## 🌟 Future Enhancements

- 🌍 **IP Analysis**: Add support for analyzing IP addresses.
- 🤖 **Bot Integration**: Include a Discord bot for real-time WHOIS result sharing.
- 📊 **Advanced Reporting**: Generate HTML or PDF reports with interactive visualizations.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

- Built with [python-whois](https://pypi.org/project/python-whois/).
- CLI styling powered by [colorama](https://pypi.org/project/colorama/).
- Async execution with Python's `asyncio`.

---

**Thank you for using WHOIS Tool!** 😊
