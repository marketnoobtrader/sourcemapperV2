package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// FILE READER TESTS
// ============================================================================

func TestFileReader(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := "test content"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Test FileReader
	reader, err := NewFileReader(tmpFile.Name())
	if err != nil {
		t.Fatalf("NewFileReader failed: %v", err)
	}
	defer reader.Close()

	if string(reader.Data()) != content {
		t.Errorf("Expected '%s', got '%s'", content, string(reader.Data()))
	}
}

func TestFileReaderLargeFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_large_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Create large file (>1MB to trigger mmap)
	largeContent := strings.Repeat("x", minFileSizeForMmap+100)
	if _, err := tmpFile.WriteString(largeContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	reader, err := NewFileReader(tmpFile.Name())
	if err != nil {
		t.Fatalf("NewFileReader failed for large file: %v", err)
	}
	defer reader.Close()

	if !reader.mmapped {
		t.Error("Expected mmap to be used for large file")
	}

	if len(reader.Data()) != len(largeContent) {
		t.Errorf("Expected length %d, got %d", len(largeContent), len(reader.Data()))
	}
}

func TestFileReaderNonExistent(t *testing.T) {
	_, err := NewFileReader("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

// ============================================================================
// WORKER POOL TESTS
// ============================================================================

func TestWorkerPool(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_pool_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pool := NewWorkerPool(2, 10)

	// Submit jobs
	for i := 0; i < 5; i++ {
		path := filepath.Join(tmpDir, "file_"+string(rune('0'+i))+".txt")
		pool.Submit(fileWriteJob{
			path: path,
			data: "content " + string(rune('0'+i)),
		})
	}

	// Close and collect results
	go pool.Close()

	successCount := 0
	for i := 0; i < 5; i++ {
		result := <-pool.Results()
		if result.success {
			successCount++
		}
	}

	if successCount != 5 {
		t.Errorf("Expected 5 successful writes, got %d", successCount)
	}

	// Verify files exist
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 5 {
		t.Errorf("Expected 5 files, got %d", len(files))
	}
}

func TestWorkerPoolConcurrency(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_concurrent_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pool := NewWorkerPool(5, 100)

	// Submit many jobs
	jobCount := 50
	for i := 0; i < jobCount; i++ {
		path := filepath.Join(tmpDir, "file_"+string(rune('0'+(i%10)))+".txt")
		pool.Submit(fileWriteJob{
			path: path,
			data: "test content",
		})
	}

	go pool.Close()

	successCount := 0
	for i := 0; i < jobCount; i++ {
		result := <-pool.Results()
		if result.success {
			successCount++
		}
	}

	if successCount != jobCount {
		t.Errorf("Expected %d successful writes, got %d", jobCount, successCount)
	}
}

// ============================================================================
// HTTP CLIENT TESTS
// ============================================================================

func TestNewHTTPClient(t *testing.T) {
	cfg := httpClientConfig{
		timeout:      30 * time.Second,
		retries:      3,
		insecure:     true,
		followRedirs: true,
		maxRedirs:    10,
	}

	client := newHTTPClient(cfg)
	if client == nil {
		t.Error("newHTTPClient returned nil")
	}
}

func TestHTTPClientConfig(t *testing.T) {
	cfg := httpClientConfig{
		timeout:      15 * time.Second,
		retries:      5,
		insecure:     false,
		followRedirs: false,
		maxRedirs:    5,
	}

	if cfg.retries != 5 {
		t.Errorf("Expected retries=5, got %d", cfg.retries)
	}

	if cfg.insecure {
		t.Error("Expected insecure=false")
	}

	if cfg.followRedirs {
		t.Error("Expected followRedirs=false")
	}
}

// ============================================================================
// CONTENT FETCHER TESTS
// ============================================================================

func TestLocalFileFetcher(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_fetch_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := "fetcher test content"
	tmpFile.WriteString(content)
	tmpFile.Close()

	fetcher := &LocalFileFetcher{path: tmpFile.Name()}
	data, err := fetcher.Fetch()
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if string(data) != content {
		t.Errorf("Expected '%s', got '%s'", content, string(data))
	}
}

func TestDataURIFetcher(t *testing.T) {
	// Base64 encoded "hello"
	uri := "data:text/plain;base64,aGVsbG8="

	fetcher := &DataURIFetcher{uri: uri}
	data, err := fetcher.Fetch()
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if string(data) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(data))
	}
}

func TestDataURIFetcherInvalid(t *testing.T) {
	uri := "data:invalid"

	fetcher := &DataURIFetcher{uri: uri}
	_, err := fetcher.Fetch()
	if err == nil {
		t.Error("Expected error for invalid data URI")
	}
}

func TestGetFetcherLocal(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_get_fetcher_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fetcher, err := GetFetcher(tmpFile.Name(), nil, nil)
	if err != nil {
		t.Fatalf("GetFetcher failed: %v", err)
	}

	if _, ok := fetcher.(*LocalFileFetcher); !ok {
		t.Error("Expected LocalFileFetcher")
	}
}

func TestGetFetcherDataURI(t *testing.T) {
	uri := "data:text/plain;base64,dGVzdA=="

	fetcher, err := GetFetcher(uri, nil, nil)
	if err != nil {
		t.Fatalf("GetFetcher failed: %v", err)
	}

	if _, ok := fetcher.(*DataURIFetcher); !ok {
		t.Error("Expected DataURIFetcher")
	}
}

func TestGetFetcherUnsupported(t *testing.T) {
	_, err := GetFetcher("ftp://example.com/file.txt", nil, nil)
	if err == nil {
		t.Error("Expected error for unsupported scheme")
	}
}

// ============================================================================
// PRIORITY CALCULATOR TESTS
// ============================================================================

func TestCalculateFilePriority(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		minScore int
		maxScore int
	}{
		{
			name:     "Source file without query",
			path:     "webpack://app/src/App.vue",
			content:  "export default { async mounted() { await fetch() } }",
			minScore: 1000,
			maxScore: 2000,
		},
		{
			name:     "Compiled file with query",
			path:     "webpack://app/src/App.vue?5d74",
			content:  "var render = function() { return _vm._self._c('div') }",
			minScore: -1000,
			maxScore: 0,
		},
		{
			name:     "Small compiled file",
			path:     "webpack://app/src/App.vue?abc",
			content:  "export { render }",
			minScore: -100,
			maxScore: 100,
		},
		{
			name:     "Large source with Vue lifecycle",
			path:     "webpack://app/src/Component.vue",
			content:  strings.Repeat("x", 2000) + "methods: { async fetchData() {} }",
			minScore: 1100,
			maxScore: 2000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calculateFilePriority(tt.path, tt.content)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("Score %d not in expected range [%d, %d]", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestPriorityRules(t *testing.T) {
	if len(priorityRules) == 0 {
		t.Error("No priority rules defined")
	}

	// Test each rule individually
	for _, rule := range priorityRules {
		if rule.name == "" {
			t.Error("Rule has empty name")
		}
		if rule.checkFunc == nil {
			t.Errorf("Rule '%s' has nil checkFunc", rule.name)
		}
	}
}

func TestSelectBestCandidate(t *testing.T) {
	candidates := []fileCandidate{
		{sourcePath: "file1", priority: 100, index: 0},
		{sourcePath: "file2", priority: 500, index: 1},
		{sourcePath: "file3", priority: 200, index: 2},
	}

	best := selectBestCandidate(candidates)
	if best.index != 1 {
		t.Errorf("Expected index 1 (highest priority), got %d", best.index)
	}
	if best.priority != 500 {
		t.Errorf("Expected priority 500, got %d", best.priority)
	}
}

// ============================================================================
// PATH PROCESSOR TESTS
// ============================================================================

func TestPathProcessorNormalize(t *testing.T) {
	pp := NewPathProcessor()

	tests := []struct {
		input    string
		expected string
	}{
		{"App.vue?5d74", "App_5d74.vue"},
		{"App.vue", "App.vue"},
		{"dir/App.vue?abc", "dir/App_abc.vue"},
		{"./file.js", "file.js"},
	}

	for _, tt := range tests {
		result := pp.Normalize(tt.input)
		if result != tt.expected {
			t.Errorf("Normalize(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestPathProcessorSanitize(t *testing.T) {
	pp := NewPathProcessor()

	tests := []struct {
		input    string
		expected string
	}{
		{"webpack://app/src/App.vue", "app/src/App.vue"}, // Chỉ remove webpack:// prefix
		{"file|with|pipes", "file_with_pipes"},
		{"file:with:colons", "file_with_colons"},
		{"file<with>brackets", "file_with_brackets"},
		{"normal/path/file.js", "normal/path/file.js"},
	}

	for _, tt := range tests {
		result := pp.Sanitize(tt.input)
		if result != tt.expected {
			t.Errorf("Sanitize(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestPathProcessorProcess(t *testing.T) {
	pp := NewPathProcessor()

	input := "webpack://app/src/Component.vue?5d74"
	result := pp.Process(input)

	// Should normalize, sanitize, and clean
	if strings.Contains(result, "webpack://") {
		t.Error("Process should remove webpack:// prefix")
	}
	if strings.Contains(result, "?5d74") {
		t.Error("Process should handle query params")
	}
}

// ============================================================================
// URL PROCESSING TESTS
// ============================================================================

func TestCategorizeURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"app.js.map", true},
		{"app.js.map?v=123", true},
		{"app.js", false},
		{"sourceMappingURL=app.map", true},
		{"sourceMap", true},
		{"index.html", false},
	}

	for _, tt := range tests {
		result := categorizeURL(tt.url)
		if result != tt.expected {
			t.Errorf("categorizeURL(%s) = %v, want %v", tt.url, result, tt.expected)
		}
	}
}

func TestDeduplicateURLs(t *testing.T) {
	urls := []string{
		"http://example.com/a.js",
		"http://example.com/b.js",
		"http://example.com/a.js", // duplicate
		"http://example.com/c.js",
		"http://example.com/b.js", // duplicate
	}

	result := deduplicateURLs(urls)
	if len(result) != 3 {
		t.Errorf("Expected 3 unique URLs, got %d", len(result))
	}

	// Check order preservation
	expected := []string{
		"http://example.com/a.js",
		"http://example.com/b.js",
		"http://example.com/c.js",
	}

	for i, url := range expected {
		if result[i] != url {
			t.Errorf("Position %d: expected %s, got %s", i, url, result[i])
		}
	}
}

func TestParseHeaders(t *testing.T) {
	headers := []string{
		"Authorization: Bearer token123",
		"Content-Type: application/json",
		"X-Custom-Header: value",
	}

	result := parseHeaders(headers)

	if len(result) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(result))
	}

	if result["Authorization"] != "Bearer token123" {
		t.Errorf("Authorization header incorrect: %s", result["Authorization"])
	}

	if result["Content-Type"] != "application/json" {
		t.Errorf("Content-Type header incorrect: %s", result["Content-Type"])
	}
}

func TestParseHeadersEmpty(t *testing.T) {
	result := parseHeaders([]string{})
	if len(result) != 0 {
		t.Errorf("Expected empty map, got %d entries", len(result))
	}
}

func TestReadURLsFromFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_urls_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := `http://example.com/app.js.map
# This is a comment
http://example.com/bundle.js

http://example.com/vendor.js.map
`
	tmpFile.WriteString(content)
	tmpFile.Close()

	urls, err := readURLsFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("readURLsFromFile failed: %v", err)
	}

	if len(urls) != 3 {
		t.Errorf("Expected 3 URLs, got %d", len(urls))
	}

	expected := []string{
		"http://example.com/app.js.map",
		"http://example.com/bundle.js",
		"http://example.com/vendor.js.map",
	}

	for i, expectedURL := range expected {
		if urls[i] != expectedURL {
			t.Errorf("URL %d: expected %s, got %s", i, expectedURL, urls[i])
		}
	}
}

func TestIsListFile(t *testing.T) {
	tests := []struct {
		filename string
		content  string
		expected bool
	}{
		{"urls.txt", "http://example.com/a.js\nhttp://example.com/b.js", true},
		{"urls.list", "any content", true},
		{"script.js", "console.log('hello')", false},
	}

	for _, tt := range tests {
		tmpFile, err := os.CreateTemp("", tt.filename)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		// Rename to match expected extension
		newName := filepath.Join(filepath.Dir(tmpFile.Name()), tt.filename)
		os.Rename(tmpFile.Name(), newName)
		defer os.Remove(newName)

		tmpFile.WriteString(tt.content)
		tmpFile.Close()

		result := isListFile(newName)
		if result != tt.expected {
			t.Errorf("isListFile(%s) = %v, want %v", tt.filename, result, tt.expected)
		}
	}
}

// ============================================================================
// WRITE FILE TESTS
// ============================================================================

func TestWriteFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_write_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "subdir", "test.txt")
	content := "test content"

	err = writeFile(path, content)
	if err != nil {
		t.Fatalf("writeFile failed: %v", err)
	}

	// Verify file exists
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if string(data) != content {
		t.Errorf("Expected '%s', got '%s'", content, string(data))
	}
}

func TestWriteFileCreateDirectories(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_write_dirs_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "a", "b", "c", "file.txt")
	err = writeFile(path, "content")
	if err != nil {
		t.Fatalf("writeFile should create directories: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("File was not created")
	}
}

// ============================================================================
// MIN FUNCTION TEST
// ============================================================================

func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{5, 3, 3},
		{3, 5, 3},
		{10, 10, 10},
		{-5, -3, -5},
		{0, 1, 0},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

func TestProcessSourceMapIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_integration_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create mock sourcemap
	// Note: Tất cả 3 sources sẽ tạo 3 files khác nhau vì có path khác nhau:
	// 1. App.vue (no query) -> App.vue
	// 2. App.vue?5d74 (with query) -> App_5d74.vue
	// 3. Component.vue -> Component.vue
	sm := sourceMap{
		Version: 3,
		Sources: []string{
			"webpack://app/src/App.vue",
			"webpack://app/src/App.vue?5d74",
			"webpack://app/src/Component.vue",
		},
		SourcesContent: []string{
			"export default { async mounted() { await this.fetchData() } }", // High priority
			"var render = function() { return _vm._self._c('div') }",        // Low priority (compiled)
			"export default { methods: { test() {} } }",
		},
	}

	pool := NewWorkerPool(2, 10)

	processed, err := processSourceMap(sm, tmpDir, pool, false)
	if err != nil {
		t.Fatalf("processSourceMap failed: %v", err)
	}

	// Close pool and collect results
	go pool.Close()
	successCount := 0
	for i := 0; i < processed; i++ {
		result := <-pool.Results()
		if result.success {
			successCount++
		}
	}

	// Vì normalizeWebpackPath đổi App.vue?5d74 -> App_5d74.vue
	// nên sẽ có 3 files khác nhau, không bị conflict
	if processed != 3 {
		t.Errorf("Expected 3 processed files, got %d", processed)
	}

	if successCount != 3 {
		t.Errorf("Expected 3 successful writes, got %d", successCount)
	}

	// Verify App.vue (without query) has high-priority content
	appPath := filepath.Join(tmpDir, "webpack_", "app", "src", "App.vue")
	content, err := os.ReadFile(appPath)
	if err != nil {
		t.Fatalf("Failed to read App.vue: %v", err)
	}

	if !strings.Contains(string(content), "async mounted") {
		t.Error("App.vue should contain high-priority source content")
	}

	// Verify App_5d74.vue exists (compiled version with different name)
	compiledPath := filepath.Join(tmpDir, "webpack_", "app", "src", "App_5d74.vue")
	if _, err := os.Stat(compiledPath); os.IsNotExist(err) {
		t.Error("App_5d74.vue should exist as separate file")
	}

	// Verify Component.vue exists
	componentPath := filepath.Join(tmpDir, "webpack_", "app", "src", "Component.vue")
	if _, err := os.Stat(componentPath); os.IsNotExist(err) {
		t.Error("Component.vue should exist")
	}
}

// TestPrioritySelectionWithConflict tests real priority-based file selection
func TestPrioritySelectionWithConflict(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_priority_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create sourcemap where TWO sources will map to SAME output file
	// This simulates: Admin.vue (source) and Admin.vue (loader wrapper)
	sm := sourceMap{
		Version: 3,
		Sources: []string{
			"webpack://app/src/views/Admin/Admin.vue",   // Source file (high priority)
			"webpack://app/./src/views/Admin/Admin.vue", // Loader wrapper (lower priority)
		},
		SourcesContent: []string{
			// Source file - long with async/await
			"export default { async fetchUsers() { if (!this.authToken) { return; } await fetch('/api/users'); } }",
			// Loader wrapper - short
			"export default Component;",
		},
	}

	pool := NewWorkerPool(2, 10)

	processed, err := processSourceMap(sm, tmpDir, pool, true) // verbose=true to see selection
	if err != nil {
		t.Fatalf("processSourceMap failed: %v", err)
	}

	// Close pool and collect results
	go pool.Close()
	successCount := 0
	for i := 0; i < processed; i++ {
		result := <-pool.Results()
		if result.success {
			successCount++
		}
	}

	// Should create only 1 file because both sources normalize to same path
	if processed != 1 {
		t.Errorf("Expected 1 processed file (conflict resolved), got %d", processed)
	}

	if successCount != 1 {
		t.Errorf("Expected 1 successful write, got %d", successCount)
	}

	// Find the Admin.vue file
	adminPath := filepath.Join(tmpDir, "webpack_", "app", "src", "views", "Admin", "Admin.vue")
	content, err := os.ReadFile(adminPath)
	if err != nil {
		t.Fatalf("Failed to read Admin.vue: %v", err)
	}

	// Verify it's the HIGH PRIORITY source file, not the loader wrapper
	contentStr := string(content)
	if !strings.Contains(contentStr, "async fetchUsers") {
		t.Error("Admin.vue should contain source file content (high priority), not loader wrapper")
	}

	if strings.Contains(contentStr, "export default Component;") {
		t.Error("Admin.vue should NOT contain loader wrapper (low priority)")
	}

	// Verify length is from source file
	if len(contentStr) < 50 {
		t.Error("Admin.vue content too short - seems like loader wrapper was selected instead")
	}
}
