from flask import Flask, render_template, request,send_file
from flask import Flask
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash,check_password_hash
import nmap
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')


mail = Mail(app)

def init_scan_history():
    conn = sqlite3.connect("scan_history.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            open_ports INTEGER NOT NULL,
            scan_time TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_scan_history()

def init_db():
    conn = sqlite3.connect("database/users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = sqlite3.connect("database/users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password FROM users WHERE email = ?",
            (email,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
           return render_template("dashboard.html")

        return "Invalid email or password"

    return render_template("login.html")

    

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            return "Passwords do not match"

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("database/users.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hashed_password)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "An account with this email already exists"

        conn.close()

        return f"Account created successfully for {email}"

    return render_template("register.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    scan_type = request.form.get("scan_type", "service")
    port_range = request.form.get("port_range", "").strip()

    if not target:
        return "Please enter an IP address or domain"

    scan_arguments = {
        "tcp": "-sT",
        "udp": "-sU",
        "syn": "-sS",
        "service": "-sV",
        "os": "-O",
        "aggressive": "-A"
    }

    arguments = scan_arguments.get(scan_type)

    if not arguments:
        return "Invalid scan type"

    # Add selected port range to Nmap
    if port_range:
        import re

        # Allow formats such as:
        # 80
        # 80,443
        # 1-100
        # 20-25,80,443
        if not re.fullmatch(r"[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*", port_range):
            return "Invalid port range. Use formats like 80, 80,443 or 1-100."

        # Check port numbers
        for part in port_range.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))

                if start < 1 or end > 65535 or start > end:
                    return "Invalid port range. Ports must be between 1 and 65535."
            else:
                port = int(part)

                if port < 1 or port > 65535:
                    return "Invalid port number. Ports must be between 1 and 65535."

        arguments += f" -p {port_range}"

    scanner = nmap.PortScanner()

    try:
        scanner.scan(target, arguments=arguments)

        results = []

        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                ports = scanner[host][protocol].keys()

                for port in sorted(ports):
                    service = scanner[host][protocol][port]

                    results.append({
                        "port": port,
                        "state": service.get("state", "unknown"),
                        "service": service.get("name", "unknown"),
                        "version": service.get("version", "unknown")
                    })

        recommendations = []

        for result in results:
            port = result["port"]

            if port == 21:
                recommendations.append(
                    "FTP (port 21) is open. Consider using SFTP or another encrypted alternative."
                )

            elif port == 22:
                recommendations.append(
                    "SSH (port 22) is open. Use strong authentication and restrict access to trusted users."
                )

            elif port == 23:
                recommendations.append(
                    "Telnet (port 23) is open. Telnet is unencrypted; disable it and use SSH instead."
                )

            elif port == 80:
                recommendations.append(
                    "HTTP (port 80) is open. Consider using HTTPS to encrypt web traffic."
                )

            elif port == 445:
                recommendations.append(
                    "SMB (port 445) is open. Restrict access and ensure SMB security updates are installed."
                )

            elif port == 3389:
                recommendations.append(
                    "RDP (port 3389) is open. Restrict RDP access and use strong authentication."
                )

        if not recommendations:
            recommendations.append(
                "No specific recommendations were detected for the scanned ports."
            )

        # Save scan history
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scan_history
            (target, scan_type, open_ports, scan_time)
            VALUES (?, ?, ?, ?)
        """, (
            target,
            scan_type,
            len(results),
            datetime.now().strftime("%d-%m-%Y %I:%M %p")
        ))

        conn.commit()
        conn.close()

        # Get scan history
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            SELECT target, scan_type, open_ports, scan_time
            FROM scan_history
            ORDER BY id DESC
        """)

        history = cursor.fetchall()
        conn.close()

        print("PORT RANGE USED:", port_range)

        
        return render_template(
            "dashboard.html",
            target=target,
            results=results,
            recommendations=recommendations,
            history=history,
            scan_type=scan_type,
            port_range=port_range
        )

    except Exception as e:
        return f"Scan error: {e}"
    
@app.route("/generate_report", methods=["POST"])
def generate_report():
    target = request.form.get("target")
    scan_type = request.form.get("scan_type", "service")
    port_range = request.form.get("port_range","").strip()

    if not target:
        return "No target provided"

    report_time = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    scan_arguments = {
        "tcp": "-sT",
        "udp": "-sU",
        "syn": "-sS",
        "service": "-sV",
        "os": "-O",
        "aggressive": "-A"
    }

    arguments = scan_arguments.get(scan_type, "-sV")

    scanner = nmap.PortScanner()

    try:
        scanner.scan(target, arguments=arguments)

        results = []

        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                ports = scanner[host][protocol].keys()

                for port in sorted(ports):
                    service = scanner[host][protocol][port]

                    results.append({
                        "port": port,
                        "state": service.get("state", "unknown"),
                        "service": service.get("name", "unknown"),
                        "version": service.get("version", "unknown")
                    })

        recommendations = []

        for result in results:
            port = result["port"]

            if port == 21:
                recommendations.append(
                    "FTP (port 21) is open. Consider using SFTP or another encrypted alternative."
                )

            elif port == 22:
                recommendations.append(
                    "SSH (port 22) is open. Use strong authentication and restrict access."
                )

            elif port == 23:
                recommendations.append(
                    "Telnet (port 23) is open. Disable it and use SSH instead."
                )

            elif port == 80:
                recommendations.append(
                    "HTTP (port 80) is open. Consider using HTTPS."
                )

            elif port == 445:
                recommendations.append(
                    "SMB (port 445) is open. Restrict access and keep security updates installed."
                )

            elif port == 3389:
                recommendations.append(
                    "RDP (port 3389) is open. Restrict RDP access and use strong authentication."
                )

        if not recommendations:
            recommendations.append(
                "No specific recommendations were detected for the scanned ports."
            )

        import os
        os.makedirs("reports", exist_ok=True)

        filename = "reports/security_report.pdf"

        pdf = canvas.Canvas(filename, pagesize=A4)

        width, height = A4
        y = height - 60

        pdf.setFont("Helvetica-Bold", 20)
        pdf.drawString(50, y, "PORT SCANNER SECURITY REPORT")

        y -= 40

        pdf.setFont("Helvetica", 12)
        pdf.drawString(50, y, f"Target: {target}")

        y -= 25
        pdf.drawString(50, y, f"Scan Type: {scan_type}")

        y -= 25
        pdf.drawString( 50, y, f"Port Range: {port_range if port_range else 'Default Nmap ports'}")

        y -= 25
        pdf.drawString(50, y, f"Scan Date & Time: {report_time}")

        y -= 30
        pdf.drawString(50, y, "Scan Results")

        y -= 25

        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(50, y, "Port")
        pdf.drawString(110, y, "State")
        pdf.drawString(170, y, "Service")
        pdf.drawString(300, y, "Version")

        y -= 20

        pdf.setFont("Helvetica", 10)

        for result in results:
            pdf.drawString(50, y, str(result["port"]))
            pdf.drawString(110, y, result["state"])
            pdf.drawString(170, y, result["service"])
            pdf.drawString(300, y, result["version"])

            y -= 18

            if y < 100:
                pdf.showPage()
                y = height - 60
                pdf.setFont("Helvetica", 10)

        y -= 20

        if y < 150:
            pdf.showPage()
            y = height - 60

        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(50, y, "Security Recommendations")

        y -= 25

        pdf.setFont("Helvetica", 10)

        for recommendation in recommendations:
            pdf.drawString(60, y, "- " + recommendation[:95])
            y -= 20

            if y < 70:
                pdf.showPage()
                y = height - 60
                pdf.setFont("Helvetica", 10)

        pdf.save()

        return send_file(filename, as_attachment=True)

    except Exception as e:
        return f"Report generation error: {e}"
    
    
@app.route("/email_report", methods=["POST"])
def email_report():
    recipient = request.form.get("recipient")

    if not recipient:
        return "Please enter a recipient email address."

    filename = "reports/security_report.pdf"

    import os

    if not os.path.exists(filename):
        return "No report found. Please generate a PDF report first."

    try:
        msg = Message(
            subject="Port Scanner Security Report",
            sender=app.config["MAIL_USERNAME"],
            recipients=[recipient]
        )

        msg.body = """Hello,

Please find attached the latest Port Scanner Security Report.

This report was generated by the Port Scanner application.

Regards,
Port Scanner Security System
"""

        with open(filename, "rb") as pdf_file:
            msg.attach(
                "security_report.pdf",
                "application/pdf",
                pdf_file.read()
            )

        mail.send(msg)

        print("EMAIL SENT TO:", recipient)

        return "Email process completed. Check the Flask terminal."

    except Exception as e:
       print("EMAIL ERROR:", e)
       return "Email could not be sent. Please check the Flask terminal."

if __name__ == "__main__":
    app.run(debug=False)