# API Key Security - NmapX v3.0

## NVD API Key Protection

NmapX implements strict security measures to protect NVD API keys and prevent credential leakage.

### Key Security Practices

#### 1. **Secure Transmission (HTTPS Only)**
- All NVD API requests use HTTPS
- API keys are transmitted only in request headers, never in URLs
- Protects against man-in-the-middle attacks and network sniffing

#### 2. **Credential Sanitization**
API keys are automatically masked in:
- Error messages
- Debug output
- Exception reports
- Database logs

**Sanitization Examples:**
```python
# Before: Full key exposed
"Error: apiKey=super-secret-api-key-1234567890"

# After: Key masked
"Error: apiKey=****"
```

#### 3. **Safe Error Reporting**
Instead of exposing exception details that might contain API keys:
```python
# ❌ Bad (exposes sensitive data)
print(f"Request failed: {exc}")  # exc may contain header dumps with API key

# ✅ Good (safe message)
print("[CVE] Request failed (network error)")
```

The application now:
- Reports only HTTP status codes, not full exception details
- Never includes headers or request parameters in user-facing output
- Safely logs errors without credential exposure

#### 4. **API Key Masking in Logs**
The `_mask_api_key_for_logging()` function provides a safe representation:
```python
api_key = "my-secret-api-key-12345"
masked = CVEEnricher._mask_api_key_for_logging(api_key)
# masked = "my-s****ty-12345" (first 4 and last 4 chars visible for verification)
```

### Environment Variable Protection

Set your API key via environment variable (recommended):
```bash
export NVD_API_KEY="your-secret-key"
# On Windows:
set NVD_API_KEY=your-secret-key
```

Or via command-line flag:
```bash
nmapx 127.0.0.1 --cve --nvd-key "your-secret-key"
```

**Important:** Avoid including API keys in:
- Scripts or configuration files (use environment variables)
- Command history (use environment variables)
- Version control (add `.env` to `.gitignore`)

### Logging and Auditing

When using API keys, be aware:
1. **Shell History**: API keys passed via CLI may appear in shell history
   - Solution: Use environment variables instead
   - On bash: `HISTCONTROL=ignorespace` to hide commands starting with space
   
2. **Log Files**: NmapX doesn't log API keys by design
   - Session data contains query results, not credentials
   - Safe to share database backups/exports without API key leakage

3. **Process Inspection**: Tools like `ps` may show command-line arguments
   - Solution: Use environment variables
   - Use `--nvd-key` only in controlled environments

### Testing API Key Security

Unit tests verify that API keys are never exposed:
```bash
python -m pytest tests/test_security_api_key.py -v
```

Tests cover:
- `_sanitize_error_message()` — removes API keys from messages
- `_mask_api_key_for_logging()` — creates safe log representations
- Error handling — no exception details in output
- Message generation — no credentials in user-facing text

### Best Practices for Integration

If you're integrating NmapX into a larger application:

1. **Use Environment Variables**
   ```bash
   # Set in your application environment
   os.environ['NVD_API_KEY'] = api_key
   # NmapX will read it automatically
   ```

2. **Rotate Keys Regularly**
   - Change API keys periodically
   - Implement key versioning if possible

3. **Least Privilege**
   - Use separate API keys for different environments (dev, staging, prod)
   - Restrict API key permissions at the NVD level if available

4. **Monitor Usage**
   - Track API key usage patterns
   - Alert on unexpected activity
   - Set rate limits and quotas

5. **Never Log Credentials**
   ```python
   # ❌ Don't do this
   logger.debug(f"Using API key: {api_key}")
   
   # ✅ Do this
   logger.debug(f"Using API key: {CVEEnricher._mask_api_key_for_logging(api_key)}")
   ```

### Incident Response

If you believe an API key has been compromised:

1. **Revoke immediately** — Contact NVD API management
2. **Rotate key** — Generate a new API key
3. **Audit usage** — Check for unauthorized CVE queries
4. **Update environment** — Deploy new key to all systems
5. **Monitor alerts** — Watch for suspicious activity

### Known Limitations

- **Shell History**: API keys in CLI flags may appear in shell history
  - Mitigation: Use environment variables or `.env` files
  
- **Process Arguments**: `ps` or similar tools may expose CLI arguments
  - Mitigation: Use environment variables in production
  
- **Error Stack Traces**: Python tracebacks could theoretically contain headers
  - Mitigation: Application sanitizes before displaying; avoid running with `--verbose` in production

### Compliance

NmapX API key handling complies with:
- **OWASP Top 10** — Prevents sensitive data exposure (A02:2021)
- **CWE-532** — Insertion of sensitive information into log files (prevented)
- **CWE-257** — Implicit trust of client-provided data (input validation in place)

---

**Last Updated:** June 8, 2026  
**NmapX Version:** 3.0  
**Contact Security Issues:** Report privately to maintainer
