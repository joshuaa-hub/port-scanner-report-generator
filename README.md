\# 🛡️ Port Scanner Report Generator



A beginner-friendly web-based network security application built with \*\*Python, Flask, and Nmap\*\*.



The application allows users to scan an IP address or domain, view open ports and services, maintain scan history, and generate security reports in PDF format. Reports can also be sent through email.



\## 🚀 Features



\- User registration and login

\- Cybersecurity dashboard

\- IP address or domain scanning

\- Multiple Nmap scan types:

&#x20; - TCP Scan

&#x20; - UDP Scan

&#x20; - SYN Scan

&#x20; - Service Version Detection

&#x20; - OS Detection

&#x20; - Aggressive Scan

\- Custom port-range scanning

\- Display of open ports and running services

\- Scan history

\- Basic security recommendations

\- PDF security report generation

\- Email report with PDF attachment

\- Responsive cybersecurity-themed dashboard

\- Environment-variable based email configuration

\- Local SQLite database



\## 🛠️ Technologies Used



\- Python

\- Flask

\- Nmap

\- python-nmap

\- SQLite

\- HTML

\- CSS

\- ReportLab

\- Flask-Mail

\- python-dotenv



\## 📁 Project Structure



```text

Port-scanner/

│

├── app.py

├── requirements.txt

├── .gitignore

│

├── templates/

│   ├── dashboard.html

│   ├── login.html

│   └── register.html

│

├── static/

│   └── css/

│       └── style.css

│

├── database/

├── reports/

└── scanner/

