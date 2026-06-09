# Configuration

Configure BSOT with API keys and customize its behavior.

---

## Configuration File

BSOT uses a YAML configuration file located at:

- **Linux/macOS**: `~/.config/bsot/config.yaml`
- **Windows**: `%APPDATA%\bsot\config.yaml`

### View Configuration Path

```bash
bsot config path
```

### View Current Configuration

```bash
bsot config show
```

---

## API Keys

BSOT integrates with several threat intelligence services. Add your API keys to enable full functionality.

### Setting API Keys

```bash
# Via CLI
bsot config set virustotal_api_key YOUR_API_KEY
bsot config set abuseipdb_api_key YOUR_API_KEY
bsot config set greynoise_api_key YOUR_API_KEY

# View a specific key
bsot config get virustotal_api_key
```

### Configuration File Format

```yaml
# ~/.config/bsot/config.yaml

# Threat Intelligence APIs
virustotal_api_key: "your-virustotal-api-key"
abuseipdb_api_key: "your-abuseipdb-api-key"
greynoise_api_key: "your-greynoise-api-key"
otx_api_key: "your-otx-api-key"
ipinfo_token: "your-ipinfo-token"

# AI APIs
openai_api_key: "your-openai-api-key"
anthropic_api_key: "your-anthropic-api-key"

# Cloudflare (for IR containment)
cloudflare_api_token: "your-cloudflare-api-token"
cloudflare_zone_id: "your-zone-id"

# Sandbox APIs
hybrid_analysis_api_key: "your-ha-api-key"
malwarebazaar_api_key: "your-mb-api-key"
```

### Environment Variables

API keys can also be set via environment variables:

```bash
export BSOT_VIRUSTOTAL_API_KEY="your-api-key"
export BSOT_ABUSEIPDB_API_KEY="your-api-key"
export BSOT_OPENAI_API_KEY="your-api-key"
```

Environment variables take precedence over the config file.

---

## Getting API Keys

### Free Tier APIs

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| VirusTotal | 500 req/day | [virustotal.com](https://www.virustotal.com/) |
| AbuseIPDB | 1000 req/day | [abuseipdb.com](https://www.abuseipdb.com/) |
| GreyNoise | 50 req/day | [greynoise.io](https://www.greynoise.io/) |
| OTX | Unlimited | [otx.alienvault.com](https://otx.alienvault.com/) |
| IPInfo | 50k req/month | [ipinfo.io](https://ipinfo.io/) |

### AI APIs

| Service | Pricing | Sign Up |
|---------|---------|---------|
| OpenAI | Pay-per-use | [platform.openai.com](https://platform.openai.com/) |
| Anthropic | Pay-per-use | [console.anthropic.com](https://console.anthropic.com/) |

---

## Cache Configuration

BSOT caches API responses to reduce rate limiting and improve performance.

### View Cache Stats

```bash
bsot cache stats
```

### Clear Cache

```bash
bsot cache clear
```

### Cache Settings

```yaml
# ~/.config/bsot/config.yaml

# Cache TTL in seconds (default: 3600 = 1 hour)
cache_ttl: 3600

# Cache directory (default: ~/.cache/bsot)
cache_dir: "~/.cache/bsot"

# Disable cache
cache_enabled: false
```

---

## Output Configuration

### Default Output Format

```yaml
# Default output format for all commands
default_format: "text"  # or "json"

# Disable colors
no_color: false
```

### Per-Command Defaults

```yaml
# Command-specific defaults
intel:
  default_sources:
    - virustotal
    - abuseipdb
    - greynoise

file:
  default_hash_algorithm: "sha256"
```

---

## Validation

Test your configuration:

```bash
# Test all API connections
bsot config test

# Test specific service
bsot ir cf test  # Cloudflare
```

---

## Troubleshooting

### "API key not configured"

Set the API key via CLI or config file:

```bash
bsot config set virustotal_api_key YOUR_KEY
```

### "Rate limit exceeded"

Wait for the rate limit to reset, or:

1. Upgrade to a paid API tier
2. Reduce request frequency
3. Enable caching to avoid duplicate requests

### "Invalid API key"

Verify your API key is correct:

1. Log into the service's web interface
2. Regenerate the API key if needed
3. Update your configuration

---

## Next Steps

- [Quick Start tutorial](quick-start.md)
- [Explore modules](../modules/index.md)
