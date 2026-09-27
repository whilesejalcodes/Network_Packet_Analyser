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

## Web dashboard

The React dashboard calls the existing multithreaded C++ engine in `src/dpi_mt.cpp`; packet analysis is not simulated in JavaScript. The engine source and its CLI behavior are unchanged.

### Run locally or in the Replit preview

```bash
npm run dev
```

This builds the engine into `build/dpi_engine`, then starts the React/Vite dashboard and Express API on port 5000.

### Production build and start

```bash
npm run build
npm start
```

The build compiles the C++ engine, type-checks the TypeScript app, compiles the server, and builds the React client. The environment needs Node.js, `g++` with C++17 and pthread support, and the existing source tree. Replit's configured deployment uses the VM target because the analysis runs a native CPU process and temporarily retains download files in the running server.

### Analysis API

`POST /api/analyze` accepts `multipart/form-data` with a `file` field and optional repeated `blockIps`, `blockApps`, and `blockDomains` fields. The backend validates a complete classic PCAP 2.4 Ethernet capture, limits uploads to 25 MiB, and limits engine execution to 60 seconds.

The backend passes arguments to the fixed executable using an argument array (never a shell):

```text
build/dpi_engine <temporary-input.pcap> <unique-temporary-output.pcap> [--block-ip VALUE] [--block-app VALUE] [--block-domain VALUE]
```

Only options the C++ CLI supports are sent. Statistics and application/domain lists are parsed from the engine's stdout. The output PCAP record count is checked against the engine's forwarded count before a result is returned. The response includes actual engine output and an opaque URL at `GET /api/download/:id`. That download is one-time and expires after 15 minutes; input and expired/downloaded output files are removed from temporary storage.

The engine reports an overall dropped-packet count, but does not report per-rule or per-domain drop counts. The dashboard labels configured rules as submitted to the engine and does not invent individual match totals. Domain blocking is a case-sensitive substring match; application blocking uses exact, case-sensitive engine labels. Uploads are limited to classic microsecond PCAP, not PCAPNG or nanosecond PCAP.

## Project Structure

```text
├── include/                 # Header files
├── src/                     # C++ implementation
├── generate_test_pcap.py
├── test_dpi.pcap
├── CMakeLists.txt
└── README.md
```

The web application adds `client/`, `server/`, and `scripts/build-engine.mjs`; `CMakeLists.txt` remains the original packet-summary target and is not used by the web dashboard.

## Attribution

This repository is maintained for learning, experimentation, and further development.

## Disclaimer

For educational and authorized network-analysis purposes only.
