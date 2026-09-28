# CTD-MCP Server: On-Premises AI Enablement for Continuous Threat Detection

This repository contains the custom **Model Context Protocol (MCP)** server for Claroty **Continuous Threat Detection (CTD)**. It bridges an intuitive, natural language chat interface with the Claroty CTD REST API, enabling operators to query asset inventories, threat baselines, risk metrics, and vulnerability data using localized AI models without cloud dependencies.

This setup is designed for **air-gapped, secure, field-ready deployments** (e.g., in a tactical flyaway kit).

---

## Architecture Overview

The integration functions as a modular **five-layer microservice stack** running entirely on local hardware:

1. **User Interface (Open WebUI):** The web-based chat environment where operators interact with the assistant.
2. **LLM Engine (Ollama):** The execution engine hosting the local Small Language Model (SLM), processing reasoning and text generation.
3. **MCP Host/Bridge (mcpo proxy):** Translates standard OpenAI-compatible tool/function calls from Open WebUI into standard MCP stdio protocol communications.
4. **MCP Server (This Repository):** A custom Python-based application that interprets MCP tool calls, formats queries, and fetches structured JSON data from Claroty.
5. **Target Application (Claroty CTD):** The physical or virtualized CTD appliance exposing its capabilities via the REST API.

```
┌──────────────┐         ┌──────────────┐
│  Open WebUI  │ ──────> │ Ollama (SLM) │
└──────┬───────┘         └──────────────┘
       │ (OpenAI Tool Calling API)
       ▼
┌──────────────┐
│  mcpo Proxy  │ (Translates OpenAPI ─> MCP stdio)
└──────┬───────┘
       │ (MCP Protocol)
       ▼
┌──────────────┐
│  MCP Server  │ (Python Application / main.py)
└──────┬───────┘
       │ (REST API / HTTPS)
       ▼
┌──────────────┐
│ CTD Instance │
└──────────────┘

```

---

## Prerequisites

Ensure your host environment meets the following baseline criteria:

### Hardware Requirements (Recommended for local SLMs)

* **Memory:** 32GB RAM minimum
* **Preferred GPU:** Dedicated graphics card with at least 8GB VRAM 

### Software Requirements

* **Operating System:** Windows 10/11 or Windows Server (Can also be deployed on Linux/macOS)
* **Python:** Stable version of **Python 3.14.x** AND **Python 3.11.x**.  (e.g., Python 3.11.9).
  * *Note for Windows:* Uncheck "Add python.exe to PATH" during installation if you want to avoid making 3.11 the default system-wide interpreter.
* **Ollama:** Download and install the latest client from [ollama.com](https://www.google.com/url?sa=E&amp;q=https%3A%2F%2Follama.com).
* **Git:** Installed and available in your environment path.

---

## Step 1: Local LLM Setup (Ollama)

1. **Install and Run Ollama:**Ensure Ollama is running in the background. It listens on `http://127.0.0.1:11434` by default.
2. **Retrieve the Target Model:**For local tool-calling capabilities, a high-quality model like `gemma4:31b` (or a cloud-linked variant like `gemma4:31b-cloud` or `gpt-oss:20b-cloud` if testing in a connected environment) is recommended.  
To pull your model, open a terminal/PowerShell window and run:  
```  
# If using a cloud-hybrid Ollama setup:  
ollama signin  
ollama pull gemma4:31b-cloud  
# Or for local standalone models:  
ollama pull gemma4:31b  
```
3. **Context Length Setting (Important):** To support extensive tool definitions, schemas, and returning asset payloads, increase your model's context window. Configure your Open WebUI model parameters or Modelfile to set:

  * **NUM\_CTX:** `262,144` tokens

---

## Step 2: MCP Server Setup

The MCP server handles custom CTD integration logic and parses requests for assets, vulnerabilities, alerts, and system configuration [15].

1. **Clone the Repository:**  
```  
git clone https://github.com/rias-clar/CTD-MCP  
cd CTD-MCP  
```
2. **Create and Activate a Dedicated Virtual Environment:**  
```  
# Create a Python virtual environment (3.14+)
python -m venv venv  
# Activate the environment  
.\venv\Scripts\Activate.ps1  
```
3. **Install Dependencies:**  
```  
pip install -r requirements.txt  
pip install mcpo  
```
4. **Configure Environment Variables:**Create a `.env` file in the root of the `CTD-MCP` directory:  
```  
CTD_HOST=https://your-ctd-appliance-ip  
CTD_USERNAME=your_admin_username  
CTD_PASSWORD=your_secure_password  
```
5. **Server Configuration (`mcp_config.json`):** The configuration file `mcp_config.json` is cloned directly with the directory.

  * **Dynamic Mode:** By default, dynamic mode is disabled (`"USE_DYNAMIC_MODE": false`). Under this mode, the server registers its static, predefined tool modules on boot.
  * **Active Modules:** You can toggle specific capabilities (e.g., `AssetsModule`, `InsightsModule`, `VulnerabilitiesModule`, `SystemModule`) in the config's `ENABLED_MODULES` array.

---

## Step 3: Open WebUI Setup

Open WebUI acts as the frontend interface for the system. It must be installed in its own separate directory and virtual environment to keep global dependencies isolated.

1. **Create and Initialize the Environment Directory:** *must be Python version 3.11 or 3.12!*
```  
# Create a python venv with VERSION 3.11
mkdir open-webui-env  
cd open-webui-env  
py -3.11 -m venv venv  
.\venv\Scripts\Activate.ps1  
```
2. **Verify Environment Isolation &amp; Version:**  
```  
python --version  
# Expected output: Python 3.11.x  
```
3. **Install Open WebUI:**  
```  
pip install open-webui  
```

---

## Running the Application

To boot up the complete on-prem AI environment, open **three separate terminal windows** (or VS Code terminal panes) and run the following processes sequentially.

### Terminal 1: Run Ollama

If Ollama is not configured as a persistent system service, run it manually:

```
ollama serve
```

### Terminal 2: Run the MCP Server &amp; Proxy

Navigate to your `CTD-MCP` directory, activate its virtual environment, and spawn the `mcpo` HTTP-to-stdio translator:

```
cd path\to\CTD-MCP
.\venv\Scripts\Activate.ps1

# Run the MCP server with the default configuration (Dynamic Mode OFF)
mcpo --host 0.0.0.0 --port 8000 -- python main.py

# OR: Force-run with Dynamic Mode enabled (overriding mcp_config.json)
mcpo --host 0.0.0.0 --port 8000 -- python main.py --dynamic

```

### Terminal 3: Run Open WebUI

Navigate to your `open-webui-env` directory, activate its virtual environment, and serve the UI:

```
cd path\to\open-webui-env
.\venv\Scripts\Activate.ps1
open-webui serve

```

---

## Interface Integration &amp; Usage

Once both servers are operational, finalize the tool registration in the browser interface:

### 1\. Register the MCP Server in Open WebUI

1. Open your web browser and navigate to **`http://localhost:8080`**.
2. Sign up or log in to create your administrative profile.
3. Click on your profile avatar in the bottom-left corner and navigate to:  
  * **Admin Panel** --> **Settings** --> **Integrations** --> **External Tool Servers**
4. Click the **`+`** icon to add a new server and enter these parameters [55]:  
  * **Type:** `OpenAPI`
  * **Name:** `Claroty CTD MCP`
  * **Description:** `MCP Server for CTD API Integration`
  * **URL:** `http://127.0.0.1:8000` 
5. Expand the **Advanced** section and specify the schema endpoint:  
  * **URL:** `openapi.json` 
6. Click **Save**.

### 2\. Verify and Query

1. Refresh the chat interface.
2. Open a new chat session and click the clover-shaped **Integrations** icon in the chat box 
3. Verify that **Tools --> Claroty CTD MCP** is active.
4. Start querying your CTD AI Assistant about your CTD instance.

#### Example Use Cases &amp; Prompts [56]:

* **Asset Visibility:** *"Can you give me a list of all PLC assets in my environment and their current risk levels?"* 
* **Cyber Task Orders (Vulnerability Scan):** *"List all assets affected by CVE-2020-6088."*
* **Appliance Integrity:** *"Is the CTD system healthy? Check the CPU, RAM, and the status of the edge sensors."* 