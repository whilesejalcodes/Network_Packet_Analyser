# Network Packet Analyzer

A C++17-based deep packet inspection (DPI) engine for analyzing PCAP network traffic, parsing network protocols, identifying applications, and applying traffic-blocking rules.

## Features

- PCAP packet reading and processing
- Ethernet, IPv4, TCP, and UDP parsing
- Five-tuple-based flow tracking
- TLS SNI and HTTP Host extraction
- Application classification
- IP-, application-, and domain-based blocking
- Multithreaded packet processing
- Traffic statistics and reporting

## Tech Stack

- **C++17**
- **Python**
- **PCAP**
- **TCP/IP**
- **Multithreading**
- **CMake**

## Architecture

```text
PCAP Input
    ↓
Packet Parser
    ↓
Flow Tracking
    ↓
DPI / SNI Extraction
    ↓
Application Classification
    ↓
Blocking Rules
    ↓
Output PCAP
```

## Build

### Simple version

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
  src/main_working.cpp src/pcap_reader.cpp \
  src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

### Multithreaded version

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
  src/dpi_mt.cpp src/pcap_reader.cpp \
  src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

## Run

```bash
./dpi_engine test_dpi.pcap output.pcap
```

To apply blocking rules:

```bash
./dpi_engine test_dpi.pcap output.pcap \
  --block-app YouTube \
  --block-domain facebook
```

## Project Structure

```text
├── include/                 # Header files
├── src/                     # C++ implementation
├── generate_test_pcap.py
├── test_dpi.pcap
├── CMakeLists.txt
└── README.md
```

## Attribution

This repository is maintained for learning, experimentation, and further development.

## Disclaimer

For educational and authorized network-analysis purposes only.
