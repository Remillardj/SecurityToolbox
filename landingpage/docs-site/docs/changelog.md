# Changelog

All notable changes to BSOT will be documented here.

---

## [Unreleased]

### Added

- Initial documentation site
- Marketing site

---

## [1.0.0] - 2025-01-01

### Added

- **Phishing Module**: Complete email analysis with header parsing, IOC extraction, AI analysis
- **Intel Module**: IOC enrichment via VirusTotal, AbuseIPDB, GreyNoise, OTX, IPInfo
- **File Module**: File hashing, identification, string extraction, entropy analysis
- **Network Module**: SSL/TLS analysis, HTTP header auditing, DNS security checks
- **Logs Module**: Log parsing (syslog, JSON, CLF, CEF) and attack pattern detection
- **Data Module**: Encoding/decoding (base64, URL, hex, HTML, etc.), timestamp conversion
- **Auth Module**: Password strength analysis with breach checking, JWT decoding
- **System Module**: Process and network connection analysis
- **IR Module**: Forensic artifact collection, containment, Cloudflare integration
- **Malware Module**: PE analysis, YARA scanning, deobfuscation, sandbox submission
- **Report Module**: Case management, AI-powered report generation, IOC export
- **OSINT Module**: Scaffolded for future development

### Features

- Unified CLI interface with consistent patterns
- JSON output support for automation
- Configurable API keys via config file or environment variables
- Caching for API responses
- Async operations for performance
- Rich terminal output with colors and formatting

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 1.0.0 | 2025-01-01 | Initial release |

---

## Versioning

BSOT follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

