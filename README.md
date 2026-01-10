# 🛡️ Trivy-dashboard
This project provides a Bash script (`scan.sh`) that runs [Trivy](https://github.com/aquasecurity/trivy) vulnerability scans on multiple Docker hosts (local and remote) and generates a clean HTML dashboard per server.
An Nginx container serves the generated reports so you can browse them easily in a browser on port `8888`.

---

## ✨ Features
- Scan **multiple Docker hosts** (local and remote via SSH)
- Automatically **update the Trivy vulnerability database** per host before scanning
- Generate a **color‑coded HTML dashboard**:
  - One collapsible section per server
  - Per image:
    - Container name (or “unused image”)
    - Image name and tag
    - Approximate image age (days)
    - Count of CRITICAL and HIGH vulnerabilities
    - Direct link to the full Trivy HTML report
- **Back to Dashboard** button on every per‑image HTML report
- **Safe Bash implementation**:
  - No `eval`
  - `set -Eeuo pipefail`
  - Temporary files on remote hosts cleaned up
- Designed to run well under **cron**, with predictable `PATH` and easy logging
- Simple **Nginx frontend via Docker Compose** to serve the reports

---

## 📂 Repository Structure
A typical layout for this project:

```text
.
├── scan.sh                     # Main Bash script (entry point)
├── html.tpl                    # Trivy HTML template
├── hosts.txt                   # List of Docker hosts to scan
├── trivy_reports/              # Generated HTML reports & dashboard
├── docker-compose.yml          # Nginx container serving ./trivy_reports
└── README.md                   # This file
```

## ⚙️ Requirements
One Linux host to host the script and dashboard with:
- Bash
- Docker Engine & Docker Compose
- SSH Key-based access to remote hosts
- Trivy
- jq for parsing JSON

On al hosts you want to scan:
- Trivy
- SSH key-based access
## Install Trivy following the official documentation: 
See https://github.com/aquasecurity/trivy

## 🚀 Usage
1. Clone the repo

2. Configure hosts.txt

### One host per line; comments and empty lines are ignored
```
localhost
docker-node-01
docker-node-02
user@remote-server.example.com
```
The script will treat localhost as a local Docker host and use SSH for all other lines
Ensure passwordless SSH (SSH keys) is configured for the remote hosts you specify.

3. Trivy HTML template

Place your Trivy HTML template as html.tpl next to scan.sh. One is provided in this repo, but you can change it or replace it.
You can start from the official examples in the Trivy repository or your own customized template.

4. Make the script executable

```bash
chmod +x scan.sh
```

5. Run a manual scan
```bash
./scan.sh
```
After completion, the dashboard will be written to:
```text
./trivy_reports/index.html
```

🌐 Viewing reports via Nginx (Docker Compose)

This repository includes a simple docker-compose.yml that runs an Nginx container serving the generated reports on port 8888:
```text
services:
  nginx:
    image: nginx:alpine-slim
    container_name: trivy_reports
    restart: unless-stopped
    volumes:
      - ./trivy_reports:/usr/share/nginx/html:ro
    ports:
      - 8888:80
```
To start Nginx, from the repository root do:
```bash
docker compose up -d
```
Now open the dashboard in your browser:

    http://localhost:8888/index.html

Every time you run ./scan.sh, the files in ./trivy_reports are updated, and Nginx will serve the new versions automatically. Don't forget to refresh your browser tab

## 🕒 Scheduling with cron
To run the scan every night at 02:00 and keep one log file per weekday (rotating weekly):
```bash
0 2 * * * /path/to/repo/scan.sh 2>&1 | tee -a /path/to/repo/logs/scan_$(date +\%A).log
```
Notes:
- $(date +\%A) expands to the weekday name (Monday, Tuesday, …) — the backslash before % is required in crontab.
- Create the log directory in advance:
  ```bash
  mkdir -p /path/to/repo/logs
  ```

## 🎨 Color‑coded server labels
Each server gets a consistent color label on the dashboard, based on a hash of the hostname.
The script maps hostnames to color classes (e.g. srv-color-0..srv-color-9) defined in the embedded CSS, helping you visually distinguish servers even when names are similar.

## 🔐 Security & Hardening
The script is written with help of an LLM, prompted to keep safety and cron‑use in mind. 
- set -Eeuo pipefail to fail early on errors
- Explicit PATH set at the top to avoid surprises under cron
- No use of eval or other dangerous dynamic shell constructs
- Input file (hosts.txt) is treated as plain data:
- Comments (# ...) and empty lines are ignored

Remote template use:
- A temporary template path per remote run
- Temporary files on remote hosts are removed after use

### I am not a guru, I used an LLM so you should review and adapt the script to your environment and security policies before using it in production.

## 📄 License
This project is licensed under the MIT License, a widely used permissive open‑source license.
See the LICENSE file for the full text.

## 🤖 AI Assistance Disclaimer
This project was created  with assistance from a Large Language Model (LLM).
If you notice bugs, security issues, or have improvements, please open an issue or a pull request.

## 🙌 Contributions
Contributions are welcome:

- Report issues
- Suggest improvements (code, security, UX)
- Open pull requests with enhancements

If you use this project in your environment and extend it (e.g. Kubernetes support, email reports, CI integration), feel free to share your enhancements back with the community.
