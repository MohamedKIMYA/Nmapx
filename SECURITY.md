# Security Policy - NmapX v3.0

## Command Injection Prevention

NmapX implements strict input validation to prevent command injection attacks when building and executing nmap commands.

### Input Validation

All user-provided inputs are validated before being passed to the nmap subprocess:

#### 1. **Target Validation** (`_validate_target`)
- Validates IP addresses (IPv4, IPv6)
- Validates CIDR notation (e.g., `192.168.0.0/24`)
- Validates hostnames (alphanumeric, dots, hyphens only)
- Rejects empty strings and shell metacharacters

Valid targets:
```
127.0.0.1
192.168.0.0/24
example.com
sub.domain.example.com
```

Invalid targets:
```
127.0.0.1;id
$(whoami)
`nmap`
```

#### 2. **Port Specification Validation** (`_validate_port_spec`)
- Allows only digits, commas, hyphens, and colons
- Rejects any shell metacharacters
- Validates format like `80,443` or `1-1024`

Valid port specs:
```
80,443
1-1024
80,443,8000-9000
```

Invalid port specs:
```
80;443
80$(id)
80|cat
```

#### 3. **Script Arguments Validation** (`_validate_script_args`)
- Rejects shell metacharacters: `;`, `|`, `&`, `$`, `` ` ``, `(`, `)`, `{`, `}`, `<`, `>`
- Only allows key=value pairs separated by commas
- Examples of safe arguments: `http.useragent=nmapx,ftp.anon=true`

Valid script args:
```
http.useragent=nmapx
ftp.anon=true,ssh.user=root
```

Invalid script args:
```
arg=value;id
arg=value|cat
$(nmap)
```

#### 4. **Exclude List Validation** (`_validate_exclude_list`)
- Validates each IP/CIDR is well-formed
- Uses `ipaddress` module for strict validation
- Comma-separated list of IPs/CIDRs

Valid exclude lists:
```
192.168.1.1
10.0.0.0/8
192.168.1.1,10.0.0.0/24
```

Invalid exclude lists:
```
192.168.1.999
invalid.ip
192.168.1.1;id
```

#### 5. **Proxy URL Validation** (`_validate_proxies`)
- Requires `http://`, `https://`, or `socks5://` schemes
- Rejects shell metacharacters in URLs
- Comma-separated list of proxy URLs

Valid proxies:
```
http://proxy.example.com:8080
https://secure.proxy.com:3128
socks5://127.0.0.1:1080
```

Invalid proxies:
```
ftp://invalid.proxy
http://proxy.com;id
http://proxy.com$(whoami)
```

### Error Handling

When invalid input is detected:
1. An error message is printed to the console with the `[!]` prefix
2. The scan is aborted early without calling nmap
3. An error event is recorded in the database with reason
4. Progress bar is updated and user is informed

### Safe Command Building

The command array is built element-by-element using `list.extend()` and `list.append()`, which prevents shell interpretation even if individual elements contain special characters (since no shell invocation occurs).

### Testing

Security validation is covered by pytest unit tests:
- `test_validate_port_spec_*` — port specification tests
- `test_validate_target_*` — target validation tests
- `test_validate_script_args_*` — script argument safety tests
- `test_validate_exclude_list_*` — exclude list validation tests
- `test_validate_proxies_*` — proxy URL validation tests

Run tests with:
```bash
python -m pytest tests/test_scanner.py::test_validate_* -v
```

### Notes for Web Application Deployment

If NmapX is integrated into a web application:

1. **Always validate user input** on the server-side (not in the browser)
2. **Use allowlists** for targets, ports, and profiles
3. **Rate-limit scans** to prevent abuse
4. **Audit all scans** with timestamps, user IDs, and input parameters
5. **Run nmap with minimal privileges** (non-root user in containers)
6. **Isolate nmap execution** in a sandbox or container with network restrictions
7. **Monitor nmap resource usage** (CPU, memory, network bandwidth)

## API Key Security

NmapX implements strict security measures to protect NVD API keys from being exposed in error messages, logs, or exception reports.

### API Key Handling

- **Transmission**: All NVD API requests use HTTPS
- **Storage**: API keys passed via environment variable or CLI flag (never embedded in code)
- **Logging**: API keys are automatically sanitized before any output

### Credential Sanitization

The `_sanitize_error_message()` function removes API keys from error messages:

```python
# Before sanitization
"Error: Failed with apiKey=super-secret-api-key-1234567890"

# After sanitization
"Error: Failed with apiKey=****"
```

### Error Message Safety

Instead of exposing full exception tracebacks:

```python
# ❌ Bad (may expose API key in headers)
except Exception as e:
    print(f"Error: {e}")

# ✅ Good (safe message only)
except httpx.HTTPStatusError as exc:
    print(f"[CVE] HTTP error {exc.response.status_code}")
```

### Best Practices

1. **Use Environment Variables** (recommended)
   ```bash
   export NVD_API_KEY="your-secret-key"
   nmapx 127.0.0.1 --cve
   ```

2. **Avoid Command-Line Flags** in production
   ```bash
   # ❌ Key may appear in process list and shell history
   nmapx 127.0.0.1 --cve --nvd-key "your-secret-key"
   ```

3. **Rotate Keys Regularly**
   - Change API keys periodically
   - Implement key versioning if possible

4. **Monitor for Exposure**
   - Check logs for API key patterns
   - Alert on unauthorized CVE query activity

For detailed API security guidance, see [API_SECURITY.md](API_SECURITY.md).

### Testing

API key security is covered by pytest tests:
- `test_sanitize_error_message_with_api_key` — message sanitization
- `test_mask_api_key_for_logging_*` — masking functions
- `test_sanitize_does_not_expose_full_key` — verification

Run tests with:
```bash
python -m pytest tests/test_security_api_key.py -v
```

### Reported Vulnerabilities

Please report security vulnerabilities to the maintainer privately. Do not open public GitHub issues for security vulnerabilities.

---

**Last Updated:** June 8, 2026  
**NmapX Version:** 3.0
