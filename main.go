package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/edsrzf/mmap-go"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/retryablehttp-go"
)

// sourceMap represents a sourceMap. We only really care about the sources and
// sourcesContent arrays.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// httpClientConfig holds HTTP client configuration
type httpClientConfig struct {
	timeout      time.Duration
	retries      int
	insecure     bool
	proxy        *url.URL
	headers      map[string]string
	followRedirs bool
	maxRedirs    int
}

// fileWriteJob represents a file write task
type fileWriteJob struct {
	path     string
	data     string
	priority int // priority: higher = more important (source files have higher priority)
}

// fileWriteResult represents the result of a file write operation
type fileWriteResult struct {
	path    string
	success bool
	err     error
}

// options represents command line options
type options struct {
	Output      string
	URLs        goflags.StringSlice // URLs, paths, or list files - auto-detect all
	List        string              // File containing URLs (for compatibility)
	Stdin       bool                // Read URLs from stdin for pipeline
	Proxy       string
	Timeout     int
	Retries     int
	RateLimit   int
	Insecure    bool
	Headers     goflags.StringSlice
	Concurrency int
	Silent      bool
	Verbose     bool
}

// newHTTPClient creates a configured retryable HTTP client
func newHTTPClient(cfg httpClientConfig) *retryablehttp.Client {
	// Create transport
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.insecure,
		},
		DisableKeepAlives: false,
	}

	// Add proxy if configured
	if cfg.proxy != nil {
		transport.Proxy = http.ProxyURL(cfg.proxy)
	}

	// Create base HTTP client
	httpClient := &http.Client{
		Timeout:   cfg.timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.followRedirs {
				return http.ErrUseLastResponse
			}
			if len(via) >= cfg.maxRedirs {
				return errors.New("stopped after max redirects")
			}
			return nil
		},
	}

	// Create Options struct for retryablehttp
	options := retryablehttp.Options{
		HttpClient:   httpClient,
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 5 * time.Second,
		Timeout:      cfg.timeout,
		RetryMax:     cfg.retries,
	}

	// Create retryable client
	client := retryablehttp.NewClient(options)

	return client
}

// parseHeaders converts headerList to map
func parseHeaders(headers []string) map[string]string {
	headerMap := make(map[string]string)

	if len(headers) == 0 {
		return headerMap
	}

	headerString := strings.Join(headers, "\r\n") + "\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(headerString))
	tpReader := textproto.NewReader(r)
	mimeHeader, err := tpReader.ReadMIMEHeader()

	if err != nil {
		log.Printf("[!] Error parsing headers: %v", err)
		return headerMap
	}

	for key, values := range mimeHeader {
		if len(values) > 0 {
			headerMap[key] = values[0]
		}
	}

	return headerMap
}

// minFileSizeForMmap is the minimum file size (in bytes) for using memory mapping.
const minFileSizeForMmap = 1024 * 1024 // 1MB

// FileReader manages file reading with automatic mmap optimization
type FileReader struct {
	path     string
	data     []byte
	mmapped  bool
	mmapData mmap.MMap
}

// NewFileReader creates a new file reader with automatic mmap for large files
func NewFileReader(path string) (*FileReader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fr := &FileReader{path: path}

	// Use memory mapping for large files
	if info.Size() >= minFileSizeForMmap {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		mmapData, err := mmap.Map(f, mmap.RDONLY, 0)
		if err != nil {
			return nil, err
		}

		fr.data = mmapData
		fr.mmapData = mmapData
		fr.mmapped = true
	} else {
		// Regular read for small files
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		fr.data = data
		fr.mmapped = false
	}

	return fr, nil
}

// Data returns the file content
func (fr *FileReader) Data() []byte {
	return fr.data
}

// Close releases resources (unmaps if needed)
func (fr *FileReader) Close() error {
	if fr.mmapped && fr.mmapData != nil {
		return fr.mmapData.Unmap()
	}
	return nil
}

// getSourceMap retrieves a sourcemap from a URL or a local file and returns
// its sourceMap.
func getSourceMap(source string, client *retryablehttp.Client, headers map[string]string) (m sourceMap, err error) {
	var body []byte

	log.Printf("[+] Retrieving Sourcemap from %.1024s...\n", source)

	// Try local file first
	if _, statErr := os.Stat(source); statErr == nil {
		reader, err := NewFileReader(source)
		if err != nil {
			return m, err
		}
		defer reader.Close()

		body = reader.Data()
	} else {
		// Not a local file, try parsing as URL
		u, err := url.ParseRequestURI(source)
		if err != nil {
			return m, err
		}

		if u.Scheme == "http" || u.Scheme == "https" {
			// If it's a URL, get it.
			req, err := retryablehttp.NewRequest("GET", u.String(), nil)
			if err != nil {
				return m, err
			}

			// Set headers
			for key, value := range headers {
				req.Header.Set(key, value)
			}

			res, err := client.Do(req)
			if err != nil {
				return m, err
			}
			defer res.Body.Close()

			body, err = io.ReadAll(res.Body)
			if err != nil {
				return m, err
			}

			if res.StatusCode != 200 && len(body) > 0 {
				log.Printf("[!] WARNING - non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode)
				log.Printf("[!] WARNING - sourceMap URL request return != 200 - however, body length > 0 so continuing... ")
			}

		} else if u.Scheme == "data" {
			urlchunks := strings.Split(u.Opaque, ",")
			if len(urlchunks) < 2 {
				return m, errors.New("could not parse data URI - expected at least 2 chunks")
			}

			data, err := base64.StdEncoding.DecodeString(urlchunks[1])
			if err != nil {
				return m, err
			}

			body = []byte(data)
		} else {
			return m, errors.New("unsupported URL scheme: " + u.Scheme)
		}
	}

	// Unmarshal the body into the struct.
	log.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))
	err = sonic.Unmarshal(body, &m)

	if err != nil {
		log.Printf("[!] Error parsing JSON - confirm %s is a valid JS sourcemap", source)
		return m, err
	}

	return m, nil
}

// getSourceMapFromJS queries a JavaScript URL, parses its headers and content and looks for sourcemaps
// follows the rules outlined in https://tc39.es/source-map-spec/#linking-generated-code
func getSourceMapFromJS(jsurl string, client *retryablehttp.Client, headers map[string]string) (m sourceMap, err error) {
	log.Printf("[+] Retrieving JavaScript from URL: %s\n", jsurl)

	// perform the request
	u, err := url.ParseRequestURI(jsurl)
	if err != nil {
		return m, err
	}

	req, err := retryablehttp.NewRequest("GET", u.String(), nil)
	if err != nil {
		return m, err
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	res, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return m, errors.New("non-200 status code: " + res.Status)
	}

	var sourceMap string

	// check for SourceMap and X-SourceMap (deprecated) headers
	if sourceMap = res.Header.Get("SourceMap"); sourceMap == "" {
		sourceMap = res.Header.Get("X-SourceMap")
	}

	if sourceMap != "" {
		log.Printf("[.] Found SourceMap URI in response headers: %.1024s...", sourceMap)
	} else {
		// parse the javascript
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return m, err
		}

		// JS file can have multiple source maps in it, but only the last line is valid https://sourcemaps.info/spec.html#h.lmz475t4mvbx
		re := regexp.MustCompile(`\/\/[@#] sourceMappingURL=(.*)`)
		match := re.FindAllSubmatch(body, -1)

		if len(match) != 0 {
			// only the sourcemap at the end of the file should be valid
			sourceMap = string(match[len(match)-1][1])
			log.Printf("[.] Found SourceMap in JavaScript body: %.1024s...", sourceMap)
		}
	}

	// this introduces a forced request bug if the JS file we're parsing is
	// malicious and forces us to make a request out to something dodgy - take care
	if sourceMap != "" {
		var sourceMapURL *url.URL
		// handle absolute/relative rules
		sourceMapURL, err = url.ParseRequestURI(sourceMap)
		if err != nil {
			// relative url...
			sourceMapURL, err = u.Parse(sourceMap)
			if err != nil {
				return m, err
			}
		}

		return getSourceMap(sourceMapURL.String(), client, headers)
	}

	return m, errors.New("no sourcemap URL found")
}

// writeFile writes content to file at path p.
func writeFile(p string, content string) error {
	p = filepath.Clean(p)

	if _, err := os.Stat(filepath.Dir(p)); os.IsNotExist(err) {
		// Using MkdirAll here is tricky, because even if we fail, we might have
		// created some of the parent directories.
		err = os.MkdirAll(filepath.Dir(p), 0700)
		if err != nil {
			return err
		}
	}

	log.Printf("[+] Writing %d bytes to %s.\n", len(content), p)
	return os.WriteFile(p, []byte(content), 0600)
}

// WorkerPool manages concurrent file write operations
type WorkerPool struct {
	workers    int
	jobs       chan fileWriteJob
	results    chan fileWriteResult
	workersWG  sync.WaitGroup
	activeJobs int
	jobsMutex  sync.Mutex
}

// NewWorkerPool creates a new worker pool for file operations
func NewWorkerPool(workers int, bufferSize int) *WorkerPool {
	wp := &WorkerPool{
		workers: workers,
		jobs:    make(chan fileWriteJob, bufferSize),
		results: make(chan fileWriteResult, bufferSize),
	}

	// Start workers
	for i := 0; i < workers; i++ {
		wp.workersWG.Add(1)
		go wp.worker()
	}

	return wp
}

// worker processes file write jobs
func (wp *WorkerPool) worker() {
	defer wp.workersWG.Done()

	for job := range wp.jobs {
		err := writeFile(job.path, job.data)
		wp.results <- fileWriteResult{
			path:    job.path,
			success: err == nil,
			err:     err,
		}
	}
}

// Submit submits a new job to the worker pool
func (wp *WorkerPool) Submit(job fileWriteJob) {
	wp.jobsMutex.Lock()
	wp.activeJobs++
	wp.jobsMutex.Unlock()

	wp.jobs <- job
}

// Close closes the worker pool and waits for all workers to finish
func (wp *WorkerPool) Close() {
	close(wp.jobs)
	wp.workersWG.Wait()
	close(wp.results)
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan fileWriteResult {
	return wp.results
}

// ActiveJobs returns the number of submitted jobs
func (wp *WorkerPool) ActiveJobs() int {
	wp.jobsMutex.Lock()
	defer wp.jobsMutex.Unlock()
	return wp.activeJobs
}

// calculateFilePriority determines the priority of a source file
// Higher priority = more likely to be the original source code
func calculateFilePriority(sourcePath string, content string) int {
	priority := 0

	// Remove webpack prefix for analysis
	cleanPath := strings.TrimPrefix(sourcePath, "webpack://")
	parts := strings.Split(cleanPath, "/")
	if len(parts) > 0 {
		cleanPath = strings.Join(parts[1:], "/")
	}

	// Check if it has query parameters (like .vue?5d74)
	hasQuery := strings.Contains(cleanPath, "?")

	// Priority rules (higher = better):
	// 1. Files WITHOUT query params are usually original source
	if !hasQuery {
		priority += 1000
	}

	// 2. Check content characteristics
	contentLen := len(content)

	// Original source files are usually longer and more readable
	if contentLen > 1000 {
		priority += 100
	}

	// 3. Check for source code patterns (vs compiled/minified code)
	if strings.Contains(content, "async ") || strings.Contains(content, "await ") {
		priority += 50
	}

	if strings.Contains(content, "export default") {
		priority += 30
	}

	// Check for Vue/React component patterns
	if strings.Contains(content, "mounted()") ||
		strings.Contains(content, "created()") ||
		strings.Contains(content, "methods:") {
		priority += 40
	}

	// 4. Penalize render functions and compiled code
	if strings.Contains(content, "var render = function") ||
		strings.Contains(content, "staticRenderFns") {
		priority -= 500
	}

	if strings.Contains(content, "_vm._self._c") {
		priority -= 300
	}

	return priority
}

// processSourceMap extracts and writes source files from a sourcemap with smart priority handling
func processSourceMap(sm sourceMap, outdir string, concurrency int, verbose bool) (int, error) {
	log.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries.\n", sm.Version, len(sm.Sources))

	if len(sm.Sources) == 0 {
		return 0, errors.New("no sources found")
	}

	if len(sm.SourcesContent) == 0 {
		return 0, errors.New("no source content found")
	}

	// Determine how many entries we can safely process
	maxEntries := len(sm.Sources)
	if len(sm.SourcesContent) < maxEntries {
		log.Printf("[!] WARNING: sourcesContent array (%d entries) is shorter than sources array (%d entries).",
			len(sm.SourcesContent), len(sm.Sources))
		log.Printf("[!] Only processing the first %d entries that have content available.", len(sm.SourcesContent))
		maxEntries = len(sm.SourcesContent)
	} else if len(sm.SourcesContent) > len(sm.Sources) {
		log.Printf("[!] WARNING: sourcesContent array (%d entries) is longer than sources array (%d entries).",
			len(sm.SourcesContent), len(sm.Sources))
		log.Printf("[!] Extra content entries will be ignored.")
	}

	if sm.Version != 3 {
		log.Println("[!] Sourcemap is not version 3. This is untested!")
	}

	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		err = os.MkdirAll(outdir, 0700)
		if err != nil {
			return 0, err
		}
	}

	// Phase 1: Analyze and group files by their final output path
	type fileCandidate struct {
		sourcePath string
		content    string
		priority   int
		index      int
	}

	fileGroups := make(map[string][]fileCandidate) // final path -> list of candidates

	for i := 0; i < maxEntries; i++ {
		sourcePath := normalizeWebpackPath(sm.Sources[i])
		sourcePath = sanitizePath(sourcePath)
		sourcePath = strings.TrimPrefix(sourcePath, "/")
		sourcePath = filepath.Clean(sourcePath)

		if runtime.GOOS == "windows" {
			sourcePath = cleanWindows(sourcePath)
		}

		// Calculate the final output path
		finalPath := filepath.Join(outdir, sourcePath)

		// Calculate priority for this file
		priority := calculateFilePriority(sm.Sources[i], sm.SourcesContent[i])

		fileGroups[finalPath] = append(fileGroups[finalPath], fileCandidate{
			sourcePath: sourcePath,
			content:    sm.SourcesContent[i],
			priority:   priority,
			index:      i,
		})
	}

	// Phase 2: Create worker pool and submit jobs
	pool := NewWorkerPool(concurrency, len(fileGroups))

	// Submit jobs - only the highest priority file for each path
	for finalPath, candidates := range fileGroups {
		// Find the candidate with highest priority
		bestCandidate := candidates[0]
		for _, candidate := range candidates[1:] {
			if candidate.priority > bestCandidate.priority {
				bestCandidate = candidate
			}
		}

		if verbose && len(candidates) > 1 {
			log.Printf("[*] Multiple sources for %s: selected source #%d (priority: %d) over %d others",
				finalPath, bestCandidate.index, bestCandidate.priority, len(candidates)-1)
			for _, c := range candidates {
				if c.index != bestCandidate.index {
					log.Printf("    - Skipped source #%d (priority: %d)", c.index, c.priority)
				}
			}
		}

		pool.Submit(fileWriteJob{
			path:     finalPath,
			data:     bestCandidate.content,
			priority: bestCandidate.priority,
		})
	}

	// Phase 3: Collect results
	go pool.Close() // Close pool in background after all jobs submitted

	processedCount := 0
	totalJobs := pool.ActiveJobs()

	for i := 0; i < totalJobs; i++ {
		result := <-pool.Results()
		if result.success {
			processedCount++
		} else {
			log.Printf("[!] Error writing %s file: %s", result.path, result.err)
		}
	}

	log.Printf("[+] Successfully wrote %d unique files (from %d total sources)\n", processedCount, maxEntries)
	return processedCount, nil
}

func sanitizePath(path string) string {
	// Handle common webpack prefixes
	if strings.HasPrefix(path, "webpack://") {
		parts := strings.Split(path, "/")
		if len(parts) > 2 {
			path = strings.Join(parts[2:], "/")
		}
	}

	// Replace invalid filename characters (platform-specific)
	invalidChars := []string{"|", "*", ":", "<", ">", "\""}

	for _, char := range invalidChars {
		path = strings.ReplaceAll(path, char, "_")
	}

	return path
}

func cleanWindows(path string) string {
	// Windows has additional reserved names
	reserved := []string{"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}

	parts := strings.Split(path, string(filepath.Separator))
	for i, part := range parts {
		upperPart := strings.ToUpper(part)
		for _, res := range reserved {
			if upperPart == res {
				parts[i] = part + "_"
				break
			}
		}
	}

	return strings.Join(parts, string(filepath.Separator))
}

// isListFile checks if a path is likely a list file based on content or extension
func isListFile(path string) bool {
	// Check file extension first
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".txt" || ext == ".list" {
		return true
	}

	// For files without these extensions, check content
	// (only if the file exists locally)
	if _, err := os.Stat(path); err == nil {
		// Read first few lines to check format
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineCount := 0
		urlCount := 0

		// Check first 5 lines
		for scanner.Scan() && lineCount < 5 {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			lineCount++
			// Check if line looks like a URL or path
			if strings.HasPrefix(line, "http://") ||
				strings.HasPrefix(line, "https://") ||
				strings.HasPrefix(line, "/") ||
				strings.HasSuffix(line, ".map") ||
				strings.HasSuffix(line, ".js") {
				urlCount++
			}
		}

		// If most lines look like URLs/paths, treat as list file
		return urlCount > 0 && float64(urlCount)/float64(lineCount) > 0.5
	}

	return false
}

// readURLsFromFile reads URLs from a file and categorizes them
func readURLsFromFile(path string) (mapURLs []string, jsURLs []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var urls []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	mapURLs, jsURLs = categorizeURLs(urls)
	return mapURLs, jsURLs, nil
}

// categorizeURLs splits URLs into sourcemap URLs and JavaScript URLs
func categorizeURLs(urls []string) (mapURLs []string, jsURLs []string) {
	for _, u := range urls {
		// Clean up URL
		u = strings.TrimSpace(u)

		// Check if it's explicitly a sourcemap URL or JS file
		if strings.HasSuffix(u, ".map") ||
			strings.Contains(u, ".map?") {
			mapURLs = append(mapURLs, u)
		} else if strings.HasSuffix(u, ".js") ||
			strings.Contains(u, ".js?") {
			jsURLs = append(jsURLs, u)
		} else {
			// For ambiguous cases, check content
			if strings.Contains(u, "sourceMappingURL") || strings.Contains(u, "sourceMap") {
				mapURLs = append(mapURLs, u)
			} else {
				// Default to JS
				jsURLs = append(jsURLs, u)
			}
		}
	}
	return mapURLs, jsURLs
}

// readURLsFromStdin reads URLs from stdin for pipeline integration
func readURLsFromStdin() ([]string, error) {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// deduplicateURLs removes duplicate URLs while preserving order
func deduplicateURLs(urls []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			unique = append(unique, url)
		}
	}

	return unique
}

// processInput handles all input sources and returns categorized URLs
func processInput(inputs []string, silent bool) (mapURLs []string, jsURLs []string, err error) {
	var allMapURLs []string
	var allJsURLs []string

	for _, input := range inputs {
		// Check if input is a list file
		if isListFile(input) {
			mapURLsFromFile, jsURLsFromFile, err := readURLsFromFile(input)
			if err != nil {
				return nil, nil, err
			}

			allMapURLs = append(allMapURLs, mapURLsFromFile...)
			allJsURLs = append(allJsURLs, jsURLsFromFile...)

			if !silent {
				log.Printf("[+] Loaded %d URLs from list file %s (%d sourcemaps, %d JavaScript)\n",
					len(mapURLsFromFile)+len(jsURLsFromFile), input, len(mapURLsFromFile), len(jsURLsFromFile))
			}
		} else {
			// Treat as direct URL/path
			mapURLsDirect, jsURLsDirect := categorizeURLs([]string{input})
			allMapURLs = append(allMapURLs, mapURLsDirect...)
			allJsURLs = append(allJsURLs, jsURLsDirect...)
		}
	}

	return allMapURLs, allJsURLs, nil
}

func main() {
	opts := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Extract source code from JavaScript sourcemaps (OPTIMIZED VERSION)")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&opts.URLs, "url", "u", nil, "URL/path to .map/.js file or list file (comma-separated)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opts.List, "list", "l", "", "file containing URLs (one per line)"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&opts.Output, "output", "o", "", "output directory (required)"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVarP(&opts.Proxy, "proxy", "p", "", "proxy URL (http/socks5)"),
		flagSet.IntVarP(&opts.Timeout, "timeout", "t", 30, "request timeout in seconds"),
		flagSet.IntVarP(&opts.Retries, "retries", "r", 3, "number of retries"),
		flagSet.IntVarP(&opts.RateLimit, "rate-limit", "rl", 0, "requests per second (0 = unlimited)"),
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", 5, "concurrent file writes"),
		flagSet.BoolVarP(&opts.Insecure, "insecure", "k", true, "skip TLS verification"),
		flagSet.StringSliceVarP(&opts.Headers, "header", "H", nil, "custom HTTP headers (can be used multiple times)", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "silent mode (errors only)"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose mode"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	// Validation
	if opts.Output == "" {
		log.Fatal("output directory is required (-o)")
	}

	var allInputs []string

	// Collect all inputs
	allInputs = append(allInputs, opts.URLs...)

	// Add list file if provided
	if opts.List != "" {
		allInputs = append(allInputs, opts.List)
	}

	// Read from stdin if requested
	if opts.Stdin {
		stdinURLs, err := readURLsFromStdin()
		if err != nil {
			log.Fatalf("Error reading from stdin: %v", err)
		}
		allInputs = append(allInputs, stdinURLs...)
	}

	if len(allInputs) == 0 {
		log.Fatal("at least one input is required (-u or -l)")
	}

	// Process all input sources
	mapURLs, jsURLs, err := processInput(allInputs, opts.Silent)
	if err != nil {
		log.Fatalf("Error processing input: %v", err)
	}

	if len(mapURLs) == 0 && len(jsURLs) == 0 {
		log.Fatal("no valid URLs/paths found in input")
	}

	// Deduplicate URLs
	allURLs := append(mapURLs, jsURLs...)
	originalCount := len(allURLs)
	mapURLs = deduplicateURLs(mapURLs)
	jsURLs = deduplicateURLs(jsURLs)

	if !opts.Silent && originalCount != (len(mapURLs)+len(jsURLs)) {
		log.Printf("[+] Removed %d duplicate URLs\n", originalCount-(len(mapURLs)+len(jsURLs)))
	}

	if !opts.Silent && (len(mapURLs) > 0 || len(jsURLs) > 0) {
		log.Printf("[+] Total: %d sourcemap URLs, %d JavaScript URLs\n", len(mapURLs), len(jsURLs))
	}

	// Parse proxy URL
	var proxyURL *url.URL
	if opts.Proxy != "" {
		proxyURL, err = url.Parse(opts.Proxy)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Parse headers
	headerMap := parseHeaders(opts.Headers)
	if len(headerMap) > 0 && opts.Verbose {
		log.Printf("[+] Using %d custom header(s)\n", len(headerMap))
	}

	// Create HTTP client config
	httpCfg := httpClientConfig{
		timeout:      time.Duration(opts.Timeout) * time.Second,
		retries:      opts.Retries,
		insecure:     opts.Insecure,
		proxy:        proxyURL,
		headers:      headerMap,
		followRedirs: true,
		maxRedirs:    10,
	}

	// Create retryable HTTP client
	client := newHTTPClient(httpCfg)

	if opts.Verbose {
		log.Printf("[+] HTTP Client configured: timeout=%ds, retries=%d, insecure=%v\n",
			opts.Timeout, opts.Retries, opts.Insecure)
	}

	totalProcessed := 0
	totalFailed := 0
	totalSources := 0

	// Rate limiter setup
	var rateLimiter <-chan time.Time
	if opts.RateLimit > 0 {
		if opts.Verbose {
			log.Printf("[+] Rate limit: %d requests/second\n", opts.RateLimit)
		}
		ticker := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// Process sourcemap URLs
	for idx, sourceURL := range mapURLs {
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}

		if !opts.Silent {
			log.Printf("\n[*] Processing sourcemap %d/%d: %s\n", idx+1, len(mapURLs), sourceURL)
		}

		sm, err := getSourceMap(sourceURL, client, headerMap)
		if err != nil {
			log.Printf("[!] Failed to retrieve sourcemap from %s: %v\n", sourceURL, err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, opts.Output, opts.Concurrency, opts.Verbose)
		if err != nil {
			log.Printf("[!] Failed to process sourcemap from %s: %v\n", sourceURL, err)
			totalFailed++
			continue
		}

		totalProcessed += processed
		totalSources++
	}

	// Process JavaScript URLs
	for idx, jsURL := range jsURLs {
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}

		if !opts.Silent {
			log.Printf("\n[*] Processing JavaScript %d/%d: %s\n", idx+1, len(jsURLs), jsURL)
		}

		sm, err := getSourceMapFromJS(jsURL, client, headerMap)
		if err != nil {
			log.Printf("[!] Failed to retrieve sourcemap from %s: %v\n", jsURL, err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, opts.Output, opts.Concurrency, opts.Verbose)
		if err != nil {
			log.Printf("[!] Failed to process sourcemap from %s: %v\n", jsURL, err)
			totalFailed++
			continue
		}

		totalProcessed += processed
		totalSources++
	}

	if !opts.Silent {
		log.Println("\n" + strings.Repeat("=", 60))
		log.Printf("[+] SUMMARY: Processed %d sourcemaps successfully, %d failed", totalSources, totalFailed)
		log.Printf("[+] Total source files extracted: %d", totalProcessed)
		log.Println("[+] Done")
	}
}

func normalizeWebpackPath(p string) string {
	dir := filepath.Dir(p)
	base := filepath.Base(p) // App.vue?5d74

	var name, hash string
	if strings.Contains(base, "?") {
		split := strings.SplitN(base, "?", 2)
		name = split[0]
		hash = split[1]
	} else {
		name = base
	}

	ext := filepath.Ext(name)
	nameOnly := strings.TrimSuffix(name, ext)

	if hash != "" {
		base = fmt.Sprintf("%s_%s%s", nameOnly, hash, ext)
	} else {
		base = name
	}

	// GHÉP LẠI path
	if dir == "." {
		return base
	}
	return filepath.Join(dir, base)
}
