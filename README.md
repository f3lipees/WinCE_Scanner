
# Overview

The tool employs over ***20 different encoding techniques*** to identify directory traversal vulnerabilities. We're not just checking for ***basic ../ patterns***, we're testing unicode bypasses, double encoding, and windows CE-specific path formats that attackers actually use in the wild. Windows CE applications often handle serialized data without proper validation. Our tests probe multiple serialization formats ***(JSON, XML, binary)*** with payloads designed to detect unsafe deserialization that could lead to remote code execution.

# Prerequisites

- Python 3.7 or higher
- Network access to target Windows CE device
- Basic understanding of your target environment

# Basic Usage

- Standard HTTP audit
  
      python windowsce_audit.py 192.168.1.100

- Custom port
  
      python windowsce_audit.py 192.168.1.100 8080

- With timeout adjustment for slow embedded systems
  
      python windowsce_audit.py 192.168.1.100 80 --timeout 30

- The tool outputs structured JSON that's designed for both human review and automated processing.

# False Positives

- Windows CE systems can be quirky. Some legitimate behaviors might trigger vulnerability alerts, especially around file access patterns. Always validate findings manually before implementing remediation measures.

# Disclaimer

- This tool is designed for security testing of systems you own or have explicit permission to test. The author of this code is not responsible for any illegal use of this tool.

# Contributing

- We highly value contributions from the community at large, and in this particular case, contributions from security researchers and industrial systems experts are welcome. Areas where we are particularly interested in improvements:

- [ ] Additional attack vectors specific to Windows CE
- [ ] Improved detection for custom industrial protocols
- [ ] Performance optimizations for large-scale scans
