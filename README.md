# Sourcemapper v2 - Optimized

High-performance tool to extract **original source code** from JavaScript sourcemaps with **intelligent priority-based file selection**. Automatically chooses the best source file when multiple versions exist.

## 🎯 Key Features

### Core Functionality
- ✅ **Smart Priority Selection** - Automatically selects original source over compiled/minified versions
- ✅ **Auto-detection** - Detects `.map` or `.js` URLs automatically
- ✅ **Pipeline Support** - Read URLs from stdin for tool chaining
- ✅ **Batch Processing** - Process multiple URLs from command line or file
- ✅ **Memory-Mapped I/O** - Fast file reading for large sourcemaps (>1MB)

### Performance & Reliability
- ✅ **Unified Worker Pool** - Shared worker pool across all sourcemaps for maximum efficiency
- ✅ **Concurrent Processing** - Parallel extraction with configurable workers
- ✅ **Auto-deduplication** - Removes duplicate URLs before processing
- ✅ **Retryable HTTP** - Auto-retry with exponential backoff
- ✅ **Rate Limiting** - Control request rate to avoid throttling

### Network & Security
- ✅ **Proxy Support** - HTTP/SOCKS5 proxy
- ✅ **Custom Headers** - Authentication and custom headers
- ✅ **TLS Configuration** - Skip verification for development environments
- ✅ **Graceful Error Handling** - Continue processing on failures

## 🚀 What's New in v2

### Intelligent File Selection

The optimizer solves a critical problem: **when multiple versions of the same file exist in a sourcemap** (e.g., `App.vue` original + `App.vue?5d74` compiled), the tool now **automatically selects the best version**.

**Priority System:**
```
Source File (no query params)         → Priority: +1000 ✅
Large file (>1KB)                     → Priority: +100
Contains async/await                  → Priority: +50
Has export default                    → Priority: +30
Vue/React lifecycle methods           → Priority: +40

Compiled render function              → Priority: -500 ❌
Vue compiled syntax (_vm._self._c)    → Priority: -300 ❌
```

**Example:**
```javascript
// Before v2: Could get compiled version (17KB render function)
var render = function() { return _vm._self._c('div', ...) }

// After v2: Always gets original source (55KB with full code)
export default {
  async fetchUsers() {
    if (!this.authToken) {
      this.message = 'Not logged in!';
      return;
    }
    const res = await fetch(`${this.apiUrl}/api/users`, {
      headers: { 'Authorization': `Bearer ${this.authToken}` }
    });
    // ... full source code
  }
}
```

### Architecture Improvements
- **ContentFetcher Interface** - Unified handling for local files, HTTP, and data URIs
- **PathProcessor** - Centralized path normalization and sanitization
- **FileReader** - Smart mmap usage for large files
- **WorkerPool** - Reusable worker pool for all operations

## 📦 Installation

```bash
go install github.com/anhnmt/sourcemapper@latest
```

Or build from source:

```bash
git clone https://github.com/anhnmt/sourcemapper
cd sourcemapper
go mod tidy
go build -o sourcemapper main_optimized_v2.go
```

## 🎮 Usage

```bash
sourcemapper [flags]

INPUT:
  -u, -url string[]     URL/path to .map/.js file or list file (auto-detect)
  -l, -list string      File containing URLs (one per line)
  -stdin                Read URLs from stdin for pipeline integration

OUTPUT:
  -o, -output string    Output directory (required)

CONFIGURATION:
  -p, -proxy string     Proxy URL (http/socks5)
  -t, -timeout int      Request timeout in seconds (default: 30)
  -r, -retries int      Number of retries (default: 3)
  -rl, -rate-limit int  Requests per second (0 = unlimited)
  -c, -concurrency int  Concurrent file writes (default: 5)
  -k, -insecure         Skip TLS verification (default: true)
  -H, -header string[]  Custom HTTP headers (repeatable)

DEBUG:
  -s, -silent           Silent mode (errors only)
  -v, -verbose          Verbose mode (shows priority selection details)
```

## 📚 Examples

### Basic Usage

```bash
# Single sourcemap URL
sourcemapper -o ./output -u https://example.com/app.js.map

# Single JavaScript URL (auto-finds sourcemap)
sourcemapper -o ./output -u https://example.com/bundle.js

# Multiple URLs (comma-separated)
sourcemapper -o ./output -u app.js.map,vendor.js,chunk.js.map

# From list file
sourcemapper -o ./output -l urls.txt

# Local files
sourcemapper -o ./output -u ./dist/app.js.map
```

### With Authentication

```bash
# API token header
sourcemapper -o ./output \
  -u https://app.example.com/bundle.js \
  -H "Authorization: Bearer YOUR_TOKEN"

# Session cookie
sourcemapper -o ./output \
  -u https://app.example.com/bundle.js \
  -H "Cookie: session=abc123"

# Multiple headers
sourcemapper -o ./output \
  -u https://app.example.com/bundle.js \
  -H "Authorization: Bearer TOKEN" \
  -H "X-API-Key: KEY123"
```

### Through Proxy

```bash
# Burp Suite proxy
sourcemapper -o ./output \
  -u https://target.com/app.js \
  -p http://127.0.0.1:8080 \
  -k

# SOCKS5 proxy
sourcemapper -o ./output \
  -u https://target.com/app.js \
  -p socks5://127.0.0.1:1080
```

### Rate Limiting

```bash
# 2 requests per second
sourcemapper -o ./output \
  -u app.js,vendor.js,chunk.js \
  -rl 2 \
  -t 60

# Slow and steady
sourcemapper -o ./output \
  -l large-list.txt \
  -rl 1 \
  -c 3
```

### Verbose Mode (See Priority Selection)

```bash
sourcemapper -o ./output -u app.js.map -v

# Output shows:
# [*] Multiple sources for output/src/App.vue: 
#     selected source #5 (priority: 1220) over 3 others
#     - Skipped source #4 (priority: -400)  ← compiled version
#     - Skipped source #6 (priority: 0)     ← style loader
#     - Skipped source #7 (priority: 1030)  ← webpack loader
```

## 🔗 Pipeline Integration

### Basic Pipeline

```bash
# Simple pipe
echo "https://example.com/app.js" | sourcemapper -o ./output -stdin

# From file
cat urls.txt | sourcemapper -o ./output -stdin

# Multiple domains
cat domains.txt | while read domain; do
  echo "https://$domain/static/js/main.js"
done | sourcemapper -o ./output -stdin
```

### With ProjectDiscovery Tools

```bash
# subfinder → httpx → katana → sourcemapper
subfinder -d target.com -silent | \
  httpx -silent -mc 200 | \
  katana -jc -silent | \
  grep -E '\.(js|map)(\?|$)' | \
  sourcemapper -o ./recon -stdin -silent

# gau → sourcemapper (archived JS files)
echo "target.com" | \
  gau | \
  grep '\.js' | \
  sort -u | \
  sourcemapper -o ./archived -stdin -rl 5

# nuclei JS endpoints → sourcemapper
nuclei -l domains.txt -t http/exposures/files/js-* -silent | \
  grep -oP 'https?://[^\s]+\.js' | \
  sort -u | \
  sourcemapper -o ./exposed -stdin

# With auth (maintain headers)
katana -u https://app.target.com \
  -H "Cookie: session=xyz" \
  -H "Authorization: Bearer token" \
  -silent | \
  grep '\.js' | \
  sourcemapper -o ./output -stdin \
    -H "Cookie: session=xyz" \
    -H "Authorization: Bearer token"
```

### Full Bug Bounty Recon Chain

```bash
#!/bin/bash
DOMAIN="$1"
OUTPUT="./recon-$DOMAIN-$(date +%Y%m%d)"

echo "[+] Starting recon for $DOMAIN"

# 1. Discover JS files
echo "[*] Discovering JavaScript files..."
subfinder -d $DOMAIN -silent | \
  dnsx -silent -resp | \
  httpx -silent -mc 200 -threads 50 | \
  katana -jc -kf all -silent -c 20 | \
  grep -E '\.(js|map)(\?|$)' | \
  sort -u > js-urls.txt

echo "[+] Found $(wc -l < js-urls.txt) JavaScript URLs"

# 2. Extract source code
echo "[*] Extracting source code..."
cat js-urls.txt | \
  sourcemapper -o $OUTPUT -stdin -rl 5 -c 10 -silent

# 3. Search for secrets
echo "[*] Searching for secrets..."
grep -r -iE "api[_-]?(key|secret|token)|password|secret|credential" $OUTPUT/ | \
  grep -v node_modules | \
  sort -u > $OUTPUT/secrets.txt

# 4. Find endpoints
echo "[*] Extracting API endpoints..."
grep -r -oE "https?://[a-zA-Z0-9./?=_%:-]*" $OUTPUT/ | \
  grep -v node_modules | \
  sort -u > $OUTPUT/endpoints.txt

# 5. Search for subdomains
echo "[*] Finding subdomains..."
grep -r -oE "[a-zA-Z0-9._-]+\.$DOMAIN" $OUTPUT/ | \
  sort -u > $OUTPUT/subdomains.txt

echo "
[+] Recon complete!
    - Source files: $OUTPUT/
    - Secrets: $(wc -l < $OUTPUT/secrets.txt) potential findings
    - Endpoints: $(wc -l < $OUTPUT/endpoints.txt) URLs
    - Subdomains: $(wc -l < $OUTPUT/subdomains.txt) found
"
```

### Advanced Pipeline Patterns

```bash
# Combine with grep for filtering
sourcemapper -o ./output -u app.js.map | \
  grep -i "api\|secret\|password"

# Process only specific file patterns
cat all-js-urls.txt | \
  grep -E '(main|bundle|chunk|vendor)\.(js|map)' | \
  sourcemapper -o ./output -stdin

# Parallel processing multiple domains
cat domains.txt | \
  parallel -j 5 "
    echo 'https://{}/static/js/main.js' | \
    sourcemapper -o ./output/{} -stdin -silent
  "
```

## 🗂️ Auto-Detection & Processing

### URL Type Detection

| Pattern | Detected Type | Action |
|---------|---------------|--------|
| `*.map` | Sourcemap | Direct extraction |
| `*.js` | JavaScript | Parse for `sourceMappingURL` |
| `*.map?v=123` | Sourcemap | Direct extraction |
| `*.js?v=123` | JavaScript | Parse for `sourceMappingURL` |
| `data:application/json;base64,...` | Data URI | Decode and parse |

### List File Detection

Files are automatically detected as list files if:
- Extension is `.txt` or `.list`, OR
- More than 50% of lines look like URLs/paths

**Example list file:**
```txt
# urls.txt - comments supported

https://app.example.com/main.js
https://app.example.com/vendor.js.map
https://cdn.example.com/chunk.js?v=1.0
./local/dist/app.js.map

# Blank lines ignored
https://static.example.com/bundle.js
```

## 📂 Output Structure

```
output/
├── webpack_/
│   └── app/
│       ├── node_modules/
│       │   ├── vue/
│       │   ├── axios/
│       │   └── ...
│       └── src/
│           ├── components/
│           │   ├── App.vue          ← Original source (priority: 1220)
│           │   ├── App_5d74.vue     ← Compiled version (saved separately)
│           │   └── Header.vue
│           ├── views/
│           │   └── Admin/
│           │       └── Admin.vue    ← Full source with async/await
│           └── utils/
└── src/
    └── ...
```

### Path Normalization

```
Input:                              Output:
webpack://app/src/App.vue          → webpack_/app/src/App.vue
webpack://app/src/App.vue?5d74     → webpack_/app/src/App_5d74.vue
./src/components/Header.vue        → src/components/Header.vue
```

## 🎯 Priority Selection Examples

### Example 1: Vue Component

```javascript
// Sourcemap contains 4 versions of Admin.vue:

// Source #4: webpack://app/./src/views/Admin/Admin.vue?ecb3
// Content: var render = function() { ... }  (17KB compiled)
// Priority: -400 ❌

// Source #5: webpack://app/src/views/Admin/Admin.vue  
// Content: export default { async fetchUsers() { ... } }  (55KB source)
// Priority: 1220 ✅ SELECTED

// Source #6: webpack://app/./src/views/Admin/Admin.vue?6113
// Content: export { render, staticRenderFns }  (280B)
// Priority: 0 ❌

// Source #7: webpack://app/./src/views/Admin/Admin.vue
// Content: export default Component;  (573B loader wrapper)
// Priority: 1030 ❌

// Result: Extracts source #5 with full original code
```

### Example 2: React Component

```javascript
// Multiple versions:

// Compiled (JSX transformed):
// Priority: -300 (has _jsx calls)
const App = () => _jsx("div", { children: "Hello" });

// Original source:
// Priority: 1120 (has async, export default, large file)
export default function App() {
  const [data, setData] = useState(null);
  
  async componentDidMount() {
    const response = await fetch('/api/data');
    setData(await response.json());
  }
  
  return <div>Hello</div>;
}

// Result: Extracts original with JSX and async code
```

## 🔧 Performance Optimization

### Memory-Mapped I/O
- Files **>1MB** use mmap for fast reading
- Files **<1MB** use regular read
- Automatic cleanup on close

### Worker Pool Efficiency
```bash
# Single worker pool shared across all sourcemaps
# Instead of creating N pools for N sourcemaps

# Before v2: 10 sourcemaps × 5 workers = 50 goroutines
# After v2:  1 pool × 5 workers = 5 goroutines ✅

sourcemapper -o ./output -l large-list.txt -c 10
# All sourcemaps use the same 10 workers
```

### Recommended Settings

```bash
# Small job (1-10 sourcemaps)
sourcemapper -o ./output -u app.js -c 5

# Medium job (10-100 sourcemaps)
sourcemapper -o ./output -l urls.txt -c 10 -rl 5

# Large job (100+ sourcemaps)
sourcemapper -o ./output -l urls.txt -c 20 -rl 10 -t 60

# Low-bandwidth / high-latency
sourcemapper -o ./output -l urls.txt -c 3 -rl 1 -t 120 -r 5
```

## 🛡️ Security & Best Practices

### ⚠️ Security Warnings

1. **Malicious JavaScript** - JS files can contain `sourceMappingURL` pointing to arbitrary URLs
2. **SSRF Risk** - Tool will fetch URLs specified in sourcemaps
3. **Data Exfiltration** - Extracted code may contain secrets/credentials

### Best Practices

```bash
# ✅ Use proxy for production targets
sourcemapper -o ./output -u https://prod.example.com/app.js -p http://127.0.0.1:8080

# ✅ Use rate limiting to avoid detection
sourcemapper -o ./output -l targets.txt -rl 2

# ✅ Use TLS verification in production
sourcemapper -o ./output -u https://target.com/app.js -k=false

# ✅ Review extracted code for secrets
grep -r "password\|secret\|api_key" ./output/

# ✅ Use timeout for slow servers
sourcemapper -o ./output -u https://slow.example.com/app.js -t 120

# ⚠️ Avoid using -k (insecure) on production without proxy
# ⚠️ Be careful with rate limits on production sites
# ⚠️ Don't commit extracted code with secrets to git
```

## 📊 Example Output

```bash
$ sourcemapper -o ./output -l urls.txt -v

[+] Loaded 15 URLs from list file urls.txt (12 sourcemaps, 3 JavaScript)
[+] Removed 3 duplicate URLs
[+] Total: 12 sourcemap URLs, 3 JavaScript URLs
[+] HTTP Client configured: timeout=30s, retries=3, insecure=true

[*] Processing sourcemap 1/12: https://app.example.com/main.js.map
[+] Retrieving Sourcemap from https://app.example.com/main.js.map...
[+] Read 245678 bytes, parsing JSON.
[+] Retrieved Sourcemap with version 3, containing 156 entries.

[*] Multiple sources for output/src/views/Admin/Admin.vue: 
    selected source #5 (priority: 1220) over 3 others
    - Skipped source #4 (priority: -400)
    - Skipped source #6 (priority: 0)
    - Skipped source #7 (priority: 1030)

[+] Queued 125 unique files (from 156 total sources)
[+] Writing 54321 bytes to output/src/views/Admin/Admin.vue.
[+] Writing 12345 bytes to output/src/components/Header.vue.
...

============================================================
[+] SUMMARY: Processed 15 sources, 0 failed
[+] Successfully wrote 1,247 files
[+] Done
```

## 🧪 Testing

```bash
# Run all tests
go test -v

# With coverage
go test -v -cover

# Specific test
go test -v -run TestPrioritySelectionWithConflict

# Benchmark
go test -bench=. -benchmem

# Integration test only
go test -v -run Integration
```

### Test Coverage
- **FileReader**: mmap optimization, cleanup
- **WorkerPool**: concurrency, deadlock prevention
- **ContentFetcher**: local files, HTTP, data URIs
- **Priority Calculator**: all priority rules
- **Path Processor**: normalization, sanitization
- **Integration**: end-to-end priority selection

## 🔍 Troubleshooting

### Common Issues

**Q: "No source content found"**
```bash
# Sourcemap has empty sourcesContent array
# Solution: Try to fetch the original JS file directly
```

**Q: "Deadlock detected"**
```bash
# If you see deadlock errors (shouldn't happen in v2):
# 1. Reduce concurrency: -c 1
# 2. Report as bug with -v flag output
```

**Q: "Getting compiled code instead of source"**
```bash
# Use -v flag to see priority selection
sourcemapper -o ./output -u app.js.map -v

# Check if source actually exists in sourcemap
# Some sourcemaps only contain compiled code
```

**Q: "Rate limited / 429 errors"**
```bash
# Reduce rate limit and increase timeout
sourcemapper -o ./output -l urls.txt -rl 1 -t 60 -r 5
```

## 📋 Error Handling

The tool gracefully handles:
- ✅ Mismatched `sources` and `sourcesContent` arrays
- ✅ Network failures (with retry)
- ✅ Invalid JSON in sourcemaps
- ✅ Invalid path characters (automatically sanitized)
- ✅ Missing directories (auto-created)
- ✅ Conflicting file paths (priority-based selection)

```bash
# Example error handling output
[!] WARNING: Array length mismatch - sources: 20, content: 16. Processing: 16
[!] WARNING - non-200 status code: 404
[!] Failed to retrieve sourcemap from https://example.com/missing.js.map: 404 Not Found
[+] Continuing with next source...
```

## 🔧 Dependencies

- **Go 1.21+**
- [github.com/bytedance/sonic](https://github.com/bytedance/sonic) - Fast JSON parser
- [github.com/edsrzf/mmap-go](https://github.com/edsrzf/mmap-go) - Memory-mapped file I/O
- [github.com/projectdiscovery/goflags](https://github.com/projectdiscovery/goflags) - CLI flags
- [github.com/projectdiscovery/retryablehttp-go](https://github.com/projectdiscovery/retryablehttp-go) - HTTP client with retry

## 🎓 How It Works

1. **Input Processing** - Parse URLs from CLI, file, or stdin
2. **Categorization** - Detect sourcemap vs JavaScript URLs
3. **Deduplication** - Remove duplicate URLs
4. **Content Fetching** - Download with retry and rate limiting
5. **Priority Analysis** - Calculate priority for each source file
6. **Conflict Resolution** - Select best version when multiple exist
7. **Worker Pool** - Concurrent file writing with shared workers
8. **Output** - Write to organized directory structure

## 📜 Credits

- **Original**: [denandz/sourcemapper](https://github.com/denandz/sourcemapper)
- **Enhanced v2**: [anhnmt](https://github.com/anhnmt)
- **Key Innovation**: Priority-based file selection system

## 📄 License

Same as original sourcemapper (check original repo for license details)

---

**v2.0.0** - Optimized with intelligent source code selection • 2026