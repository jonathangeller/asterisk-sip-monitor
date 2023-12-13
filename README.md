# Asterisk SIP Traffic Monitoring Script

## Overview
This repository contains a Bash script designed to monitor SIP (Session Initiation Protocol) traffic for hack attempts, intrusions, or otherwise fraudulent 'invites' to Asterisk-based PBX systems. It checks for failed SIP registration attempts and known malicious user agents, notifying the administrator via email if suspicious activities are detected.

## Features
- Monitors SIP traffic by analyzing Asterisk log files.
- Detects failed SIP registration attempts and known malicious user agents.
- Configurable threshold for triggering alerts.
- Email notifications for suspicious activities.
- Safe list feature to exclude known IPs from triggering alerts.

## Prerequisites
- A Linux-based operating system.
- Access to the Asterisk log files.
- A mail service (like Postfix) installed and configured on the server for sending email alerts. Ensure the mail service is correctly set up and functioning before using this script.

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/jonathangeller/asterisk-sip-monitor.git
   cd asterisk-sip-monitor
   ```

2. **Set Execution Permissions**
   ```bash
   chmod +x script.sh
   ```

3. **Configuration**
   - Edit `malicious_useragents.txt` to include any additional user agents you want to monitor.
   - Update `safe_ips.txt` with IP addresses that should be considered safe and not trigger alerts.
   - Modify the script to set your email address for receiving alerts.

## Usage
To run the script manually:
```bash
./script.sh
```

The script will scan the Asterisk log file for suspicious activities and send an email if the threshold for suspicious actions is exceeded.

## Setting up a Cron Job

To automate the running of this script at regular intervals, set up a cron job:

1. **Open the Crontab Configuration**
   ```bash
   crontab -e
   ```

2. **Add a Cron Job**
   Add the following line to the crontab file, adjusting the path to where the script is located and the interval at which you want the script to run. The following example runs the script every 5 minutes:
   ```bash
   */5 * * * * /path/to/asterisk-sip-monitor/script.sh >> /path/to/asterisk-sip-monitor/logfile.log 2>&1
   ```
   Replace `/path/to/asterisk-sip-monitor/script.sh` and `/path/to/asterisk-sip-monitor/logfile.log` with the full paths to your script and desired log file.

3. **Save and Exit**
   Save the crontab file and exit the editor. The cron job is now scheduled.

## Logs
Check `logfile.log` in the script directory for a record of the script's output and any errors encountered during execution.

## License
This project is licensed under the MIT License - see the LICENSE file for details.