# Usage Guide

This document provides detailed instructions on how to use the Network Traffic Analyzer effectively.

## Getting Started

After installation, make sure your virtual environment is activated:

```bash
# On Windows
analyvenv\Scripts\activate

# On macOS/Linux
source analyvenv/bin/activate
```

## Running the Application

### Interactive Mode

The easiest way to use the analyzer is through its interactive menu:

```bash
python analyzer.py
```

This will display a menu with several options:

```
ANALIZADOR DE TRÁFICO DE RED (SIN PRIVILEGIOS)
----------------------------------------------------------------------
OPCIONES DE CAPTURA:
1. Cargar archivo PCAP
2. Analizar conexiones activas (no requiere privilegios)
3. Realizar escaneo básico de puertos (no requiere privilegios)
4. Obtener información DNS (no requiere privilegios)
5. Generar datos simulados para demostración

ANÁLISIS Y SALIDA:
6. Generar informe
7. Visualizar datos
8. Exportar a JSON
9. Limpiar datos
0. Salir
```

### Command Line Arguments

You can also run the analyzer with command-line arguments for automation or scripting:

```bash
# General syntax
python analyzer.py [OPTIONS]

# Examples:
# Analyze a PCAP file
python analyzer.py -f path/to/capture.pcap

# Scan specific IP address
python analyzer.py -s 192.168.1.1

# Look up DNS information for specific domains
python analyzer.py -d google.com,github.com,microsoft.com

# Analyze current connections
python analyzer.py -c

# Generate simulated data (for testing)
python analyzer.py --simulate 100

# Specify output directory for generated graphics
python analyzer.py -o ./output_folder
```

## Feature Details

### 1. Working with PCAP Files

The analyzer can load and analyze packet capture (PCAP) files created with tools like Wireshark:

```bash
python analyzer.py -f capture.pcap
```

If using the interactive menu, select option 1 and provide the path to your PCAP file.

### 2. Analyzing Active Connections

This feature provides information about current network connections without requiring administrative privileges:

```bash
python analyzer.py -c
```

In interactive mode, select option 2.

### 3. Basic Port Scanning

The tool can perform basic TCP connect scans to check for open ports:

```bash
# Scan a specific IP with default ports
python analyzer.py -s 192.168.1.1

# In interactive mode, select option 3
```

When using the interactive menu, you can specify which ports to scan.

### 4. DNS Information

Retrieve DNS resolution information for specified domains:

```bash
python analyzer.py -d google.com,github.com
```

In interactive mode, select option 4 and enter the domains to query.

### 5. Simulated Data

For testing or demonstration purposes, you can generate simulated network data:

```bash
python analyzer.py --simulate 100
```

This will create 100 simulated connections. In interactive mode, select option 5.

### 6. Generating Reports

After analyzing traffic (using any of the methods above), you can generate a detailed report:

```bash
# After running any analysis command
python analyzer.py -c -s 192.168.1.1 # analyze and scan
# The report will be generated automatically
```

In interactive mode, run one or more analysis options (1-5), then select option 6.

### 7. Data Visualization

The analyzer can create graphical representations of the analyzed data:

```bash
# After analyzing traffic
python analyzer.py -c -o ./graphs
```

The `-o` parameter specifies where to save the generated graphs. In interactive mode, select option 7 after performing analysis.

### 8. Exporting to JSON

Analysis results can be exported to JSON format for further processing:

```bash
# After analyzing, results will be exported automatically
```

In interactive mode, select option 8 after performing analysis. You'll be prompted for a filename.

## Output Interpretation

### Terminal Report

The terminal report includes:
- Date and time of analysis
- Protocol distribution
- Most contacted IP addresses
- Most used destination ports
- DNS queries
- Potential anomalies

### Visualizations

The tool generates several graphs:
- Protocol distribution (bar chart)
- Most contacted IPs (bar chart)
- Most used ports (bar chart)

These are saved as PNG files in the specified output directory.

### JSON Export

The JSON export contains all the collected data in a structured format that can be processed by other tools or scripts.

## Advanced Usage

### Combining Features

You can combine multiple features in a single command:

```bash
python analyzer.py -c -s 192.168.1.1 -d google.com,github.com -o ./output
```

This will:
1. Analyze current connections
2. Scan ports on 192.168.1.1
3. Look up DNS information for google.com and github.com
4. Save visualizations to the ./output directory

### Automation and Scheduling

You can automate network analysis by creating scripts that run the analyzer with specific parameters at scheduled times.

Example Windows batch script:
```batch
@echo off
cd C:\path\to\Analisis_trafico_local
call analyvenv\Scripts\activate
python analyzer.py -c -o C:\path\to\reports\%date:~-4,4%%date:~-7,2%%date:~-10,2%
```

Example Linux/macOS shell script:
```bash
#!/bin/bash
cd /path/to/Analisis_trafico_local
source analyvenv/bin/activate
python analyzer.py -c -o /path/to/reports/$(date +%Y%m%d)
```

## Limitations

- The tool can only detect and analyze traffic that is visible to the current user without administrative privileges.
- Port scanning is limited to basic TCP connect scans.
- Packet inspection is only available when analyzing PCAP files.
