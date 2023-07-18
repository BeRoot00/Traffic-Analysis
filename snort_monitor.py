from pysnort import Snort
import time

# Create an instance of the Snort class.
snort = Snort()

# Load the rules for Snort from the specified file path
snort.load_rules("path/to/file.rules")

# Start Snort to begin monitoring for network traffic and potential intrusion attempts.
snort.start()

alerts = {}

timeout = time.time() + 10

# Enter a while loop that runs until the current time exceeds the timeout.
while time.time() < timeout:
    # Iterate through the alerts received from Snort using the snort.alerts() method.
    for alert in snort.alerts():
        # Create a tuple 'alert_key' containing the source IP and the signature of the alert. This will be used as a unique identifier for the alert.
        alert_key = (alert.src_ip, alert.signature)

        # Check if the 'alert_key' is already present in the 'alerts' dictionary. If it is, increment the occurrence count for the alert.
        if alert_key in alerts:
            alerts[alert_key]["count"] += 1
        else:
            # If the 'alert_key' is not present, add a new entry to the 'alerts' dictionary for the current alert.
            alerts[alert_key] = {
                "src_ip": alert.src_ip,
                "signature": alert.signature,
                "count": 1,
                "data": []
            }

        # Append the alert data to the 'data' list in the corresponding 'alert_key' entry in the 'alerts' dictionary.
        alerts[alert_key]["data"].append(alert.data)

# Print statistics of the alerts stored in the 'alerts' dictionary.
print("Statistics of the alerts :")
for alert_key, alert_info in alerts.items():
    print(f"Source IP : {alert_info['src_ip']}")
    print(f"Signature : {alert_info['signature']}")
    print(f"Number of occurrences : {alert_info['count']}")
    print("Additional data :")
    for data in alert_info['data']:
        print(f"  - {data}")
    print()

# Stop Snort to end the monitoring process.
snort.stop()
