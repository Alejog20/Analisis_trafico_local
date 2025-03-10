# Installation Guide

This document provides detailed instructions for installing and setting up the Network Traffic Analyzer on different operating systems.

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)
- Git (for cloning the repository)

## Installation Steps

### Windows

1. **Install Python:**
   - Download and install Python from [python.org](https://www.python.org/downloads/windows/)
   - Ensure you select "Add Python to PATH" during installation

2. **Clone the repository:**
   ```cmd
   git clone https://github.com/Alejog20/Analisis_trafico_local.git
   cd Analisis_trafico_local
   ```

3. **Create and activate a virtual environment:**
   ```cmd
   python -m venv analyvenv
   analyvenv\Scripts\activate
   ```

4. **Install dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```

### macOS

1. **Install Python:**
   - If you don't have Python installed, install it using Homebrew:
     ```bash
     brew install python
     ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/Alejog20/Analisis_trafico_local.git
   cd Analisis_trafico_local
   ```

3. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv analyvenv
   source analyvenv/bin/activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Linux (Ubuntu/Debian)

1. **Install Python and dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv git
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/Alejog20/Analisis_trafico_local.git
   cd Analisis_trafico_local
   ```

3. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv analyvenv
   source analyvenv/bin/activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Troubleshooting

### Common Issues

1. **Scapy Installation Problems:**
   - On Windows, you might need to install Npcap:
     - Download and install from [Npcap's website](https://nmap.org/npcap/)
   - On Linux, you might need additional permissions:
     ```bash
     sudo apt install libpcap-dev
     ```

2. **Matplotlib Dependencies:**
   - On Linux, you might need additional libraries:
     ```bash
     sudo apt install python3-tk
     ```

3. **Permission Issues:**
   - The tool is designed to work without administrator privileges, but some features may have limited functionality.
   - If you want full functionality, run with administrator/root privileges:
     - Windows: Run Command Prompt as Administrator
     - macOS/Linux: Use `sudo` (not recommended for security reasons)

### Error: "No module named 'scapy'"

If you get this error despite installing the requirements:

1. Make sure your virtual environment is activated
2. Try installing scapy directly:
   ```bash
   pip install scapy
   ```

## Upgrading

To update to the latest version:

```bash
git pull
pip install -r requirements.txt --upgrade
```

## Uninstallation

To uninstall, simply delete the project directory and virtual environment:

```bash
# Deactivate the virtual environment first
deactivate

# On Windows
rmdir /s /q Analisis_trafico_local

# On macOS/Linux
rm -rf Analisis_trafico_local
```
