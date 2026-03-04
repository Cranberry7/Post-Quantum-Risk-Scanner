# PQ Risk Scanner

**Post-Quantum Risk Scanner** — a static analysis tool that inventories cryptographic usage in software systems and evaluates the associated risk under post-quantum threat models.

## What It Does

1. **Scans** files (PEM certificates, TLS/SSH configs, source code) for cryptographic primitives
2. **Classifies** each primitive as `quantum-unsafe`, `quantum-weakened`, or `quantum-safe`
3. **Explains** the quantum impact using Shor's and Grover's algorithm analysis
4. **Recommends** post-quantum migration paths aligned with NIST standards

## What It Is Not

- Not a vulnerability scanner or penetration testing tool
- Not a compliance assessment platform
- Not a real-time security monitoring system
- Does not predict quantum computing timelines

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Scan a file
```bash
python cli.py scan path/to/certificate.pem
```

### Scan a directory
```bash
python cli.py scan path/to/configs/
```

### Verbose output with quantum explanations
```bash
python cli.py scan path/to/project/ -v
```

### Generate a Markdown report
```bash
python cli.py scan path/to/project/ --output-format markdown --output-file report.md
```

## Supported Inputs

| Input Type | Examples |
|------------|---------|
| PEM files | `.pem`, `.crt`, `.cer`, `.key` |
| Config files | `nginx.conf`, `sshd_config`, `.conf` |
| Source code | `.py`, `.java`, `.js`, `.ts`, `.go`, `.rs`, `.c`, `.cpp` |

## Architecture

```
Input → Scanner Layer → Analysis Layer → Quantum Reasoning → Reporting
```

- **Scanner Layer**: Detects cryptographic primitives (factual inventory)
- **Analysis Layer**: Risk classification + migration advice
- **Quantum Reasoning**: Shor's and Grover's algorithm impact explanations
- **Reporting**: Console (colored) or Markdown output

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design details.

## Risk Categories

| Category | Meaning |
|----------|---------|
| 🔴 quantum-unsafe | Broken by quantum computer (Shor's algorithm) |
| 🟡 quantum-weakened | Security reduced by Grover's algorithm |
| 🟢 quantum-safe | Adequate post-quantum security |

## License

This project is for educational and analytical purposes.
