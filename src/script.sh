#!/bin/bash

# User-configurable variables
LOG_FILE="/var/log/asterisk/full"
USERAGENTS_FILE="malicious_useragents.txt"
SAFE_IPS_FILE="safe_ips.txt"
EMAIL="your_email@example.com"
THRESHOLD_COUNT=1
THRESHOLD_TIME=30  # In seconds, used for checking the time range

# Internal variables
LAST_CHECK_TIME_FILE="/tmp/last_check_time"
FAILED_REGISTRATION_COUNT=0
MALICIOUS_UA_COUNT=0
CURRENT_TIME=$(date '+%s')

echo "Script started. Current time is $(date -d "@$CURRENT_TIME" '+%Y-%m-%d %H:%M:%S')."

# Check if log file exists
if [[ ! -f "$LOG_FILE" ]]; then
    echo "Error: Log file $LOG_FILE not found."
    exit 1
fi

# Read last check time from file, or use current time minus threshold if file doesn't exist
if [[ -f "$LAST_CHECK_TIME_FILE" ]]; then
    LAST_CHECK_TIME=$(cat "$LAST_CHECK_TIME_FILE")
    LAST_CHECK_TIME_UNIX=$(date -d "$LAST_CHECK_TIME" '+%s')
    echo "Last check time read from file: $LAST_CHECK_TIME"
else
    LAST_CHECK_TIME_UNIX=$(($CURRENT_TIME - THRESHOLD_TIME))
    LAST_CHECK_TIME=$(date -d "@$LAST_CHECK_TIME_UNIX" '+%Y-%m-%d %H:%M:%S')
    echo "Last check time file not found. Using time: $LAST_CHECK_TIME"
fi

# Function to check if IP is in the safe list
is_ip_safe() {
    local ip=$1
    if grep -Fxq "$ip" "$SAFE_IPS_FILE"; then
        return 0  # IP is safe
    else
        return 1  # IP is not safe
    fi
}

# Function to process log lines
process_log_lines() {
    local pattern=$1
    while IFS= read -r line; do
        local log_timestamp=$(echo $line | awk '{print substr($1, 2), substr($2, 1, length($2)-1)}')
        local log_time_unix=$(date -d "$log_timestamp" '+%s')

        if [[ $log_time_unix -ge $LAST_CHECK_TIME_UNIX ]]; then
            local ip=$(echo $line | awk -F\' '{print $(NF-1)}' | awk -F':' '{print $1}')
            if is_ip_safe "$ip"; then
                echo "IP $ip is in the safe list. Ignoring."
                continue
            fi

            if [[ $pattern == "Registration.from.*failed" ]]; then
                ((FAILED_REGISTRATION_COUNT++))
                echo "Failed Registration Detected: $line" >> /tmp/suspicious_activity
            elif [[ $pattern == "User-Agent:.*" ]]; then
                ((MALICIOUS_UA_COUNT++))
                echo "Malicious User Agent Detected: $line" >> /tmp/suspicious_activity
            fi
        fi
    done < <(grep -E "$pattern" "$LOG_FILE")
}

# Check for failed registrations
echo "Checking for failed registrations..."
process_log_lines "Registration.from.*failed"

# Check for known malicious user agents
echo "Checking for known malicious user agents..."
while IFS= read -r agent; do
    process_log_lines "User-Agent:.*$agent"
done < "$USERAGENTS_FILE"

# Output counts
echo "Failed registration attempts count: $FAILED_REGISTRATION_COUNT"
echo "Malicious user agents count: $MALICIOUS_UA_COUNT"

# Calculate total matches
TOTAL_MATCHES=$((FAILED_REGISTRATION_COUNT + MALICIOUS_UA_COUNT))
echo "Total suspicious activities detected: $TOTAL_MATCHES"

# Prepare email content with counts and log results
EMAIL_CONTENT="Total suspicious activities detected: $TOTAL_MATCHES\n\n"
EMAIL_CONTENT+="Failed registration attempts count: $FAILED_REGISTRATION_COUNT\n"
EMAIL_CONTENT+="Malicious user agents count: $MALICIOUS_UA_COUNT\n\n"
EMAIL_CONTENT+="--- Detected Log Entries ---\n"
EMAIL_CONTENT+=$(cat /tmp/suspicious_activity)

# Update last check time
echo $(date -d "@$CURRENT_TIME" '+%Y-%m-%d %H:%M:%S') > "$LAST_CHECK_TIME_FILE"

# Send email if threshold is exceeded
if (( TOTAL_MATCHES >= THRESHOLD_COUNT )); then
    if [[ -s /tmp/suspicious_activity ]]; then
        echo "Threshold exceeded. Sending email..."
        echo -e "$EMAIL_CONTENT" | mail -s "SIP Intrusion Alert" "$EMAIL"
    else
        echo "Threshold exceeded, but no suspicious activity detected."
    fi
else
    echo "Threshold not exceeded. No email sent."
fi

# Cleanup
> /tmp/suspicious_activity
echo "Script completed."
