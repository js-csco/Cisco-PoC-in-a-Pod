Cisco PoC in a Pod:

## Prerequisites
- prepare a Linux Ubuntu 24.04.x LTS VM


## Installation

1. Clone this repository
```bash
   git clone https://github.com/yourusername/piap-k3s.git
   cd piap-k3s/setup
```

2. Make the setup script executable and run it
```bash
   chmod +x setup-k3s.sh
   sudo ./setup-k3s.sh
```

3. Enter your Connector credentials when prompted
4. Enter your Splunk Password when prompted

5. Access your services at `http://<server-ip>:<nodeport>`




