#analisis de Trafico Local
# Network Traffic Analyzer

A comprehensive Python tool for analyzing network traffic, monitoring connections, and detecting potential anomalies without requiring administrator privileges.

![Network Analysis](https://github.com/Alejog20/Analisis_trafico_local/raw/main/docs/assets/network_banner.png)

## 🚀 Features

- Analyze network connections without requiring administrator privileges
- Perform basic port scanning on local and remote hosts
- Monitor active network connections and their states
- Collect DNS resolution information
- Visualize traffic patterns with graphs and charts
- Generate detailed reports of network activity
- Detect potential network anomalies
- Export analysis results to JSON format

## 📋 Requirements

- Python 3.6 or higher
- Dependencies:
  - scapy
  - pandas
  - matplotlib
  - psutil

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/Alejog20/Analisis_trafico_local.git
cd Analisis_trafico_local

# Create and activate virtual environment
python -m venv analyvenv
source analyvenv/bin/activate  # On Windows: analyvenv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 💻 Usage

### Command Line Interface

```bash
# Run in interactive mode
python analyzer.py

# Load and analyze a PCAP file
python analyzer.py -f capture.pcap

# Scan specific IP
python analyzer.py -s 192.168.1.1

# Check DNS for specific domains
python analyzer.py -d google.com,github.com

# Analyze active connections
python analyzer.py -c

# Generate simulated data (for testing)
python analyzer.py --simulate 100
```

### Interactive Menu

The tool provides an interactive menu with the following options:

1. Load PCAP file
2. Analyze active connections (no privileges required)
3. Perform basic port scanning (no privileges required)
4. Get DNS information (no privileges required)
5. Generate simulated data for demonstration
6. Generate report
7. Visualize data
8. Export to JSON
9. Clear data
0. Exit

## 📊 Output Examples

The tool generates various outputs, including:

- Terminal-based reports
- PNG graph visualizations
- JSON data exports

![Protocol Distribution](https://github.com/Alejog20/Analisis_trafico_local/raw/main/docs/assets/protocol_sample.png)

## 🛡️ Limitations

- This tool is designed to work without administrator privileges, which limits some functionality compared to full-featured network analyzers.
- Port scanning is limited to basic TCP connect scans.
- Deep packet inspection is only available when analyzing PCAP files.

## 📝 Open source

This project is open source.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/Alejog20/Analisis_trafico_local/issues).

## ⚠️ Disclaimer

This tool is intended for legitimate network analysis, troubleshooting, and security assessment purposes. Only use it on networks and systems you own or have explicit permission to analyze.
