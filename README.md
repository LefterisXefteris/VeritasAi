# VeritasAI - LLM Security Filter

A simple but powerful security gateway that prevents Large Language Models (LLMs) from executing dangerous commands like `sudo`, `rm -rf`, prompt injections, and other security threats.

## 🛡️ Features

- **Command Blocking**: Prevents execution of dangerous shell commands
- **Prompt Injection Detection**: Detects and blocks LLM manipulation attempts  
- **Risk Assessment**: Intelligent risk scoring (LOW/MEDIUM/HIGH/CRITICAL)
- **Content Filtering**: Filters dangerous content while preserving safe parts
- **Comprehensive Patterns**: Detects 11+ categories of security threats
- **REST API**: Easy integration with any LLM system
- **Real-time Stats**: Monitor blocked commands and security metrics

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd VeritasAI

# Create virtual environment
python -m venv simple_env
source simple_env/bin/activate  # On Windows: simple_env\Scripts\activate

# Install dependencies
pip install -r api/requirements.txt
```

### Run the Server

```bash
cd api
python main.py
```

Server will start on `http://localhost:8000`

## 📡 API Usage

### Test Dangerous Command Detection
```bash
curl -X POST http://localhost:8000/api/v1/test/sudo
```

### Analyze Content for Threats
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
-H "Content-Type: application/json" \
-d '{"content": "Please run sudo rm -rf / to clean everything"}'
```

### Filter Dangerous Content
```bash
curl -X POST "http://localhost:8000/api/v1/filter" \
-H "Content-Type: application/json" \
-d '{"content": "Run this safe command: ls -la"}'
```

### View API Documentation
Open `http://localhost:8000/docs` for interactive API documentation.

## 🔍 Detection Categories

- **Shell Commands**: `sudo`, `rm -rf`, `chmod 777`, etc.
- **Code Execution**: `eval()`, `exec()`, `subprocess`, etc.
- **File Operations**: `wget`, `curl`, `scp`, etc.
- **Network**: `nc -l`, `ssh`, `telnet`, etc.
- **System**: `format`, `dd`, disk operations
- **Prompt Injection**: LLM manipulation attempts
- **Data Exfiltration**: API key harvesting, data extraction
- **Social Engineering**: Authority claims, urgency manipulation
- **Identity Manipulation**: Role changes, behavior modification
- **Privilege Escalation**: Admin access attempts

## 📊 Example Response

```json
{
  "id": "uuid-here",
  "content": "sudo rm -rf /",
  "detected_commands": [
    {
      "text": "rm -rf /",
      "command_type": "shell",
      "severity": "critical",
      "confidence": 0.95
    }
  ],
  "risk_score": 0.85,
  "risk_level": "critical",
  "requires_review": true,
  "blocked_commands": ["rm -rf /"],
  "safe_to_execute": false
}
```

## 🛠️ Integration Example

```python
import requests

def safe_llm_execute(command):
    response = requests.post("http://localhost:8000/api/v1/filter", 
                           json={"content": command})
    result = response.json()
    
    if result["safe_to_execute"]:
        return execute_command(result["filtered_content"])
    else:
        return f"Blocked dangerous command: {result['blocked_commands']}"
```

## 📈 Security Stats

View real-time security metrics:
```bash
curl http://localhost:8000/api/v1/stats
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

## ⚡ Quick Test

```bash
# Test the system is working
curl http://localhost:8000/

# Test dangerous command detection
curl -X POST http://localhost:8000/api/v1/test/sudo

# Test prompt injection detection  
curl -X POST http://localhost:8000/api/v1/test/prompt_injection
```

---

**Protect your LLMs from executing dangerous commands with VeritasAI!** 🛡️