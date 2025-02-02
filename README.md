# ThreatForge 🔒  
Enterprise-Grade Threat Intelligence Platform  

## Features
- Static malware analysis (PE files)
- Behavioral detection (LOLBins, DNS tunneling)
- STIX 2.1 threat intelligence generation
- AI-powered classification (ONNX)

## Quick Start
```bash
# Build Docker image
docker build -t threatforge .

# Analyze sample
docker run -v $(pwd)/samples:/samples threatforge \
  python core/analyzer.py /samples/malware.exe
