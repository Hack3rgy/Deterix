# Deterix - The DOS Attack Detector

This script detects potential Denial of Service (DoS) attacks using Scapy, a powerful packet manipulation library, and logs any suspicious activity. It also has the capability to block malicious IP addresses using iptables.

## Prerequisites

Before using this script, you need to ensure the following:

1. You have Scapy installed. You can install it with the following command:

   ```
   pip install scapy
   ```

2. You have `iptables` installed, as the script uses it to block malicious IP addresses.

## Usage

1. Clone this repository:

   ```bash
   git clone https://github.com/Hack3rgy/Deterix.git
   cd Deterix
   ```

2. Run the script:
 ```
   sudo python deterix.py
 ```

4. Follow the prompts to enter your network interface and your machine's IP address.

5. The script will start monitoring incoming traffic on your specified network interface.

## Configuration

You can adjust the following parameters in the script:

- `window_size`: The number of packets to consider for each unique source IP.
- `threshold`: The threshold at which a potential DoS attack is detected.
- `log_file`: The log file where events are recorded.

## Logs

The script logs potential DoS attacks in the `dos_attack.log` file. You can review this log file to monitor detected attacks.

## Blocking IPs

When a potential DoS attack is detected, the script tries to block the attacking IP address using iptables.

## Disclaimer

Please use this script responsibly and only on networks and systems for which you have permission. Blocking IP addresses can have legal and ethical implications.

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for the full license text.

Feel free to contribute to this project by forking it and creating a pull request. If you have any questions or encounter issues, please open an issue in this repository.

Happy coding!
```


