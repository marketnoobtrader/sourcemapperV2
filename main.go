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

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

type httpClientConfig struct {
	timeout      time.Duration
	retries      int
	insecure     bool
	proxy        *url.URL
	headers      map[string]string
	followRedirs bool
	maxRedirs    int
}

type fileWriteJob struct {
	path     string
	data     string
	priority int
}

type fileWriteResult struct {
	path    string
	success bool
	err     error
}

type options struct {
	Output      string
	URLs        goflags.StringSlice
	List        string
	Stdin       bool
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

// ============================================================================
// FILE READER WITH MMAP
// ============================================================================

const minFileSizeForMmap = 1024 * 1024 // 1MB

type FileReader struct {
	data     []byte
	mmapData mmap.MMap
	mmapped  bool
}

func NewFileReader(path string) (*FileReader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fr := &FileReader{}

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
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		fr.data = data
	}

	return fr, nil
}

func (fr *FileReader) Data() []byte {
	return fr.data
}

func (fr *FileReader) Close() error {
	if fr.mmapped && fr.mmapData != nil {
		return fr.mmapData.Unmap()
	}
	return nil
}

// ============================================================================
// WORKER POOL
// ============================================================================

type WorkerPool struct {
	workers   int
	jobs      chan fileWriteJob
	results   chan fileWriteResult
	workersWG sync.WaitGroup
	jobsCount int
	mutex     sync.Mutex
}

func NewWorkerPool(workers, bufferSize int) *WorkerPool {
	wp := &WorkerPool{
		workers: workers,
		jobs:    make(chan fileWriteJob, bufferSize),
		results: make(chan fileWriteResult, bufferSize),
	}

	for i := 0; i < workers; i++ {
		wp.workersWG.Add(1)
		go wp.worker()
	}

	return wp
}

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

func (wp *WorkerPool) Submit(job fileWriteJob) {
	wp.mutex.Lock()
	wp.jobsCount++
	wp.mutex.Unlock()
	wp.jobs <- job
}

func (wp *WorkerPool) Close() {
	close(wp.jobs)
	wp.workersWG.Wait()
	close(wp.results)
}

func (wp *WorkerPool) Results() <-chan fileWriteResult {
	return wp.results
}

func (wp *WorkerPool) JobsCount() int {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()
	return wp.jobsCount
}

// ============================================================================
// HTTP CLIENT
// ============================================================================

func newHTTPClient(cfg httpClientConfig) *retryablehttp.Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.insecure},
		DisableKeepAlives:   false,
	}

	if cfg.proxy != nil {
		transport.Proxy = http.ProxyURL(cfg.proxy)
	}

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

	return retryablehttp.NewClient(retryablehttp.Options{
		HttpClient:   httpClient,
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 5 * time.Second,
		Timeout:      cfg.timeout,
		RetryMax:     cfg.retries,
	})
}

// ============================================================================
// CONTENT FETCHERS - Unified approach
// ============================================================================

type ContentFetcher interface {
	Fetch() ([]byte, error)
}

// LocalFileFetcher reads from local filesystem
type LocalFileFetcher struct {
	path string
}

func (f *LocalFileFetcher) Fetch() ([]byte, error) {
	reader, err := NewFileReader(f.path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return reader.Data(), nil
}

// HTTPFetcher reads from HTTP/HTTPS
type HTTPFetcher struct {
	url     string
	client  *retryablehttp.Client
	headers map[string]string
}

func (f *HTTPFetcher) Fetch() ([]byte, error) {
	req, err := retryablehttp.NewRequest("GET", f.url, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range f.headers {
		req.Header.Set(key, value)
	}

	res, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 && len(body) > 0 {
		log.Printf("[!] WARNING - non-200 status code: %d", res.StatusCode)
	}

	return body, nil
}

// DataURIFetcher reads from data: URI
type DataURIFetcher struct {
	uri string
}

func (f *DataURIFetcher) Fetch() ([]byte, error) {
	parts := strings.Split(strings.TrimPrefix(f.uri, "data:"), ",")
	if len(parts) < 2 {
		return nil, errors.New("invalid data URI format")
	}
	return base64.StdEncoding.DecodeString(parts[1])
}

// GetFetcher returns appropriate fetcher for the source
func GetFetcher(source string, client *retryablehttp.Client, headers map[string]string) (ContentFetcher, error) {
	// Check if it's a local file
	if _, err := os.Stat(source); err == nil {
		return &LocalFileFetcher{path: source}, nil
	}

	// Parse as URL
	u, err := url.ParseRequestURI(source)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http", "https":
		return &HTTPFetcher{url: source, client: client, headers: headers}, nil
	case "data":
		return &DataURIFetcher{uri: source}, nil
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}
}

// ============================================================================
// SOURCEMAP OPERATIONS
// ============================================================================

func fetchAndParseSourceMap(source string, client *retryablehttp.Client, headers map[string]string) (sourceMap, error) {
	log.Printf("[+] Retrieving Sourcemap from %.1024s...\n", source)

	fetcher, err := GetFetcher(source, client, headers)
	if err != nil {
		return sourceMap{}, err
	}

	body, err := fetcher.Fetch()
	if err != nil {
		return sourceMap{}, err
	}

	log.Printf("[+] Read %d bytes, parsing JSON.\n", len(body))

	var sm sourceMap
	if err := sonic.Unmarshal(body, &sm); err != nil {
		log.Printf("[!] Error parsing JSON - confirm %s is a valid JS sourcemap", source)
		return sourceMap{}, err
	}

	return sm, nil
}

func extractSourceMapURL(jsBody []byte, jsURL *url.URL) (string, error) {
	// Find sourceMappingURL in JS
	re := regexp.MustCompile(`\/\/[@#] sourceMappingURL=(.*)`)
	matches := re.FindAllSubmatch(jsBody, -1)

	if len(matches) == 0 {
		return "", errors.New("no sourcemap URL found")
	}

	// Use last match (as per spec)
	sourceMapRef := string(matches[len(matches)-1][1])
	log.Printf("[.] Found SourceMap in JavaScript body: %.1024s...", sourceMapRef)

	// Parse as absolute or relative URL
	sourceMapURL, err := url.ParseRequestURI(sourceMapRef)
	if err != nil {
		// Relative URL
		sourceMapURL, err = jsURL.Parse(sourceMapRef)
		if err != nil {
			return "", err
		}
	}

	return sourceMapURL.String(), nil
}

func getSourceMapFromJS(jsurl string, client *retryablehttp.Client, headers map[string]string) (sourceMap, error) {
	log.Printf("[+] Retrieving JavaScript from URL: %s\n", jsurl)

	u, err := url.ParseRequestURI(jsurl)
	if err != nil {
		return sourceMap{}, err
	}

	fetcher := &HTTPFetcher{url: jsurl, client: client, headers: headers}
	body, err := fetcher.Fetch()
	if err != nil {
		return sourceMap{}, err
	}

	// Try to get sourcemap URL from body
	sourceMapURL, err := extractSourceMapURL(body, u)
	if err != nil {
		return sourceMap{}, err
	}

	return fetchAndParseSourceMap(sourceMapURL, client, headers)
}

// ============================================================================
// FILE PRIORITY CALCULATOR
// ============================================================================

type PriorityRule struct {
	name      string
	checkFunc func(path, content string) bool
	score     int
}

var priorityRules = []PriorityRule{
	{"NoQueryParams", func(path, _ string) bool {
		cleanPath := strings.TrimPrefix(path, "webpack://")
		if idx := strings.Index(cleanPath, "/"); idx != -1 {
			cleanPath = cleanPath[idx+1:]
		}
		return !strings.Contains(cleanPath, "?")
	}, 1000},

	{"LargeFile", func(_, content string) bool {
		return len(content) > 1000
	}, 100},

	{"HasAsync", func(_, content string) bool {
		return strings.Contains(content, "async ") || strings.Contains(content, "await ")
	}, 50},

	{"HasExportDefault", func(_, content string) bool {
		return strings.Contains(content, "export default")
	}, 30},

	{"HasVueLifecycle", func(_, content string) bool {
		return strings.Contains(content, "mounted()") ||
			strings.Contains(content, "created()") ||
			strings.Contains(content, "methods:")
	}, 40},

	{"IsRenderFunction", func(_, content string) bool {
		return strings.Contains(content, "var render = function") ||
			strings.Contains(content, "staticRenderFns")
	}, -500},

	{"IsVueCompiled", func(_, content string) bool {
		return strings.Contains(content, "_vm._self._c")
	}, -300},
}

func calculateFilePriority(sourcePath, content string) int {
	priority := 0
	for _, rule := range priorityRules {
		if rule.checkFunc(sourcePath, content) {
			priority += rule.score
		}
	}
	return priority
}

// ============================================================================
// PATH PROCESSING
// ============================================================================

type PathProcessor struct {
	isWindows bool
}

func NewPathProcessor() *PathProcessor {
	return &PathProcessor{isWindows: runtime.GOOS == "windows"}
}

func (pp *PathProcessor) Normalize(p string) string {
	// Handle webpack path with query params
	dir := filepath.Dir(p)
	base := filepath.Base(p)

	var name, hash string
	if strings.Contains(base, "?") {
		parts := strings.SplitN(base, "?", 2)
		name = parts[0]
		hash = parts[1]
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

	if dir == "." {
		return base
	}
	return filepath.Join(dir, base)
}

func (pp *PathProcessor) Sanitize(path string) string {
	// Remove webpack prefix
	if strings.HasPrefix(path, "webpack://") {
		parts := strings.Split(path, "/")
		if len(parts) > 2 {
			path = strings.Join(parts[2:], "/")
		}
	}

	// Replace invalid chars
	for _, char := range []string{"|", "*", ":", "<", ">", "\""} {
		path = strings.ReplaceAll(path, char, "_")
	}

	return path
}

func (pp *PathProcessor) CleanWindows(path string) string {
	if !pp.isWindows {
		return path
	}

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

func (pp *PathProcessor) Process(p string) string {
	p = pp.Normalize(p)
	p = pp.Sanitize(p)
	p = strings.TrimPrefix(p, "/")
	p = filepath.Clean(p)
	p = pp.CleanWindows(p)
	return p
}

// ============================================================================
// SOURCEMAP PROCESSOR
// ============================================================================

type fileCandidate struct {
	sourcePath string
	content    string
	priority   int
	index      int
}

func processSourceMap(sm sourceMap, outdir string, pool *WorkerPool, verbose bool) (int, error) {
	log.Printf("[+] Retrieved Sourcemap with version %d, containing %d entries.\n", sm.Version, len(sm.Sources))

	if len(sm.Sources) == 0 {
		return 0, errors.New("no sources found")
	}

	if len(sm.SourcesContent) == 0 {
		return 0, errors.New("no source content found")
	}

	maxEntries := min(len(sm.Sources), len(sm.SourcesContent))

	if len(sm.SourcesContent) != len(sm.Sources) {
		log.Printf("[!] WARNING: Array length mismatch - sources: %d, content: %d. Processing: %d",
			len(sm.Sources), len(sm.SourcesContent), maxEntries)
	}

	if sm.Version != 3 {
		log.Println("[!] Sourcemap is not version 3. This is untested!")
	}

	if err := os.MkdirAll(outdir, 0700); err != nil {
		return 0, err
	}

	// Group files by output path
	fileGroups := make(map[string][]fileCandidate)
	pathProcessor := NewPathProcessor()

	for i := 0; i < maxEntries; i++ {
		sourcePath := pathProcessor.Process(sm.Sources[i])
		finalPath := filepath.Join(outdir, sourcePath)
		priority := calculateFilePriority(sm.Sources[i], sm.SourcesContent[i])

		fileGroups[finalPath] = append(fileGroups[finalPath], fileCandidate{
			sourcePath: sourcePath,
			content:    sm.SourcesContent[i],
			priority:   priority,
			index:      i,
		})
	}

	// Submit best candidate for each path
	for finalPath, candidates := range fileGroups {
		best := selectBestCandidate(candidates)

		if verbose && len(candidates) > 1 {
			logCandidateSelection(finalPath, best, candidates)
		}

		pool.Submit(fileWriteJob{
			path:     finalPath,
			data:     best.content,
			priority: best.priority,
		})
	}

	log.Printf("[+] Queued %d unique files (from %d total sources)\n", len(fileGroups), maxEntries)
	return len(fileGroups), nil
}

func selectBestCandidate(candidates []fileCandidate) fileCandidate {
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.priority > best.priority {
			best = c
		}
	}
	return best
}

func logCandidateSelection(path string, best fileCandidate, all []fileCandidate) {
	log.Printf("[*] Multiple sources for %s: selected source #%d (priority: %d) over %d others",
		path, best.index, best.priority, len(all)-1)
	for _, c := range all {
		if c.index != best.index {
			log.Printf("    - Skipped source #%d (priority: %d)", c.index, c.priority)
		}
	}
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

func writeFile(p, content string) error {
	p = filepath.Clean(p)

	dir := filepath.Dir(p)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	log.Printf("[+] Writing %d bytes to %s.\n", len(content), p)
	return os.WriteFile(p, []byte(content), 0600)
}

// ============================================================================
// URL PROCESSING
// ============================================================================

func parseHeaders(headers []string) map[string]string {
	if len(headers) == 0 {
		return make(map[string]string)
	}

	headerMap := make(map[string]string)
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

func categorizeURL(u string) (isMap bool) {
	return strings.HasSuffix(u, ".map") || strings.Contains(u, ".map?") ||
		strings.Contains(u, "sourceMappingURL") || strings.Contains(u, "sourceMap")
}

func readURLsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

func readURLsFromStdin() ([]string, error) {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

func isListFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".txt" || ext == ".list" {
		return true
	}

	// Check file content
	if _, err := os.Stat(path); err != nil {
		return false
	}

	urls, err := readURLsFromFile(path)
	if err != nil {
		return false
	}

	if len(urls) == 0 {
		return false
	}

	// Check if most lines look like URLs
	urlCount := 0
	for _, u := range urls {
		if strings.HasPrefix(u, "http") || strings.HasPrefix(u, "/") ||
			strings.HasSuffix(u, ".map") || strings.HasSuffix(u, ".js") {
			urlCount++
		}
	}

	return float64(urlCount)/float64(len(urls)) > 0.5
}

func deduplicateURLs(urls []string) []string {
	seen := make(map[string]bool, len(urls))
	unique := make([]string, 0, len(urls))

	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			unique = append(unique, url)
		}
	}

	return unique
}

func processInput(inputs []string, silent bool) (mapURLs, jsURLs []string, err error) {
	var allURLs []string

	for _, input := range inputs {
		if isListFile(input) {
			urls, err := readURLsFromFile(input)
			if err != nil {
				return nil, nil, err
			}
			allURLs = append(allURLs, urls...)

			if !silent {
				log.Printf("[+] Loaded %d URLs from list file %s\n", len(urls), input)
			}
		} else {
			allURLs = append(allURLs, input)
		}
	}

	// Categorize
	for _, u := range allURLs {
		if categorizeURL(u) {
			mapURLs = append(mapURLs, u)
		} else {
			jsURLs = append(jsURLs, u)
		}
	}

	return mapURLs, jsURLs, nil
}

// ============================================================================
// MAIN
// ============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	opts := &options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Extract source code from JavaScript sourcemaps (FULLY OPTIMIZED)")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&opts.URLs, "url", "u", nil, "URL/path to .map/.js file or list file", goflags.CommaSeparatedStringSliceOptions),
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
		flagSet.StringSliceVarP(&opts.Headers, "header", "H", nil, "custom HTTP headers", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "silent mode (errors only)"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose mode"),
	)

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Error parsing flags: %s", err)
	}

	if opts.Output == "" {
		log.Fatal("output directory is required (-o)")
	}

	// Collect inputs
	var allInputs []string
	allInputs = append(allInputs, opts.URLs...)

	if opts.List != "" {
		allInputs = append(allInputs, opts.List)
	}

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

	// Process input
	mapURLs, jsURLs, err := processInput(allInputs, opts.Silent)
	if err != nil {
		log.Fatalf("Error processing input: %v", err)
	}

	if len(mapURLs) == 0 && len(jsURLs) == 0 {
		log.Fatal("no valid URLs/paths found in input")
	}

	// Deduplicate
	originalCount := len(mapURLs) + len(jsURLs)
	mapURLs = deduplicateURLs(mapURLs)
	jsURLs = deduplicateURLs(jsURLs)

	if !opts.Silent && originalCount != (len(mapURLs)+len(jsURLs)) {
		log.Printf("[+] Removed %d duplicate URLs\n", originalCount-(len(mapURLs)+len(jsURLs)))
	}

	if !opts.Silent {
		log.Printf("[+] Total: %d sourcemap URLs, %d JavaScript URLs\n", len(mapURLs), len(jsURLs))
	}

	// Setup HTTP client
	var proxyURL *url.URL
	if opts.Proxy != "" {
		proxyURL, err = url.Parse(opts.Proxy)
		if err != nil {
			log.Fatal(err)
		}
	}

	headerMap := parseHeaders(opts.Headers)
	if len(headerMap) > 0 && opts.Verbose {
		log.Printf("[+] Using %d custom header(s)\n", len(headerMap))
	}

	client := newHTTPClient(httpClientConfig{
		timeout:      time.Duration(opts.Timeout) * time.Second,
		retries:      opts.Retries,
		insecure:     opts.Insecure,
		proxy:        proxyURL,
		headers:      headerMap,
		followRedirs: true,
		maxRedirs:    10,
	})

	if opts.Verbose {
		log.Printf("[+] HTTP Client configured: timeout=%ds, retries=%d, insecure=%v\n",
			opts.Timeout, opts.Retries, opts.Insecure)
	}

	// Create worker pool (reused for all sourcemaps)
	totalURLs := len(mapURLs) + len(jsURLs)
	pool := NewWorkerPool(opts.Concurrency, totalURLs*10)

	// Rate limiter
	var rateLimiter <-chan time.Time
	if opts.RateLimit > 0 {
		if opts.Verbose {
			log.Printf("[+] Rate limit: %d requests/second\n", opts.RateLimit)
		}
		ticker := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	totalProcessed := 0
	totalFailed := 0

	// Process all URLs
	allSources := make([]struct {
		url   string
		isMap bool
	}, 0, totalURLs)

	for _, u := range mapURLs {
		allSources = append(allSources, struct {
			url   string
			isMap bool
		}{u, true})
	}

	for _, u := range jsURLs {
		allSources = append(allSources, struct {
			url   string
			isMap bool
		}{u, false})
	}

	// Start result collector in background
	resultsDone := make(chan struct{})
	var successCount int

	go func() {
		for result := range pool.Results() {
			if result.success {
				successCount++
			} else {
				log.Printf("[!] Error writing %s: %s", result.path, result.err)
			}
		}
		close(resultsDone)
	}()

	// Process sources
	for idx, source := range allSources {
		if rateLimiter != nil {
			<-rateLimiter
		}

		if !opts.Silent {
			log.Printf("\n[*] Processing %d/%d: %s\n", idx+1, totalURLs, source.url)
		}

		var sm sourceMap
		var err error

		if source.isMap {
			sm, err = fetchAndParseSourceMap(source.url, client, headerMap)
		} else {
			sm, err = getSourceMapFromJS(source.url, client, headerMap)
		}

		if err != nil {
			log.Printf("[!] Failed: %v\n", err)
			totalFailed++
			continue
		}

		processed, err := processSourceMap(sm, opts.Output, pool, opts.Verbose)
		if err != nil {
			log.Printf("[!] Failed to process: %v\n", err)
			totalFailed++
			continue
		}

		totalProcessed += processed
	}

	// Close pool and wait for all results to be processed
	pool.Close()
	<-resultsDone

	if !opts.Silent {
		log.Println("\n" + strings.Repeat("=", 60))
		log.Printf("[+] SUMMARY: Processed %d sources, %d failed", totalURLs-totalFailed, totalFailed)
		log.Printf("[+] Successfully wrote %d files", successCount)
		log.Println("[+] Done")
	}
}
