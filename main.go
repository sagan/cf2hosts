package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync" // For concurrent CNAME resolution

	"github.com/cloudflare/cloudflare-go" // Official Cloudflare Go SDK
	"github.com/sagan/cf2hosts/util"
)

const VERSION = "v0.3.0"

// --- Configuration Variables ---
var (
	// Config: cloudflare API token
	cfToken string
	// Config: cloudflare DNS zone id
	cfZone        string
	domain        string
	excludeDomain string
	saveSRVDir    string
	identifier    string
	hostsFilePath string
	dryRun        bool
	// Optional config: for more detailed output
	verbose bool
)

// --- Hosts File Delimiters ---
const (
	HOSTS_FILE_DELIMITER_PREFIX = "# CF2HOSTS"
)

// --- Main Application Logic ---
func main() {
	fmt.Printf("cf2hosts %s\n", VERSION)
	// 1. Parse Command Line Flags and Environment Variables
	setupConfig()
	if dryRun {
		fmt.Printf("--- DRY RUN MODE ENABLED ---\n")
	}
	if verbose {
		fmt.Printf("Verbose mode enabled.\n")
	}

	// 2. Initialize Cloudflare API Client
	api, err := newCloudflareClient()
	if err != nil {
		log.Fatalf("Error creating Cloudflare client: %v", err)
	}

	// 3. Fetch DNS Records
	if verbose {
		log.Printf("Fetching DNS records for zone ID %q and domain %q", cfZone, domain)
	}
	records, err := fetchDNSRecords(api)
	if err != nil {
		log.Fatalf("Error fetching DNS records: %v", err)
	}
	for _, record := range records {
		record.Name = strings.ToLower(record.Name)
	}
	recordIps := resolveIps(records)

	if verbose {
		log.Printf("Found %d DNS records.", len(records))
	}

	// 4. Process Records
	var cnameRecords []cloudflare.DNSRecord
	var srvRecords []cloudflare.DNSRecord

	domains := strings.Split(domain, ",")
	excludeDomains := strings.Split(excludeDomain, ",")
	for i, d := range domains {
		domains[i] = strings.TrimPrefix(d, ".")
	}
	for i, d := range excludeDomains {
		excludeDomains[i] = strings.TrimPrefix(d, ".")
	}

	// 5. Handle A and CNAME Records (Update Hosts File)
	hostsEntries := make(map[string]string) // domain -> ip
	failedEntries := make(map[string]bool)

	for _, r := range records {
		// Filter for the specific domain or subdomains
		if !slices.ContainsFunc(domains, func(domain string) bool {
			return r.Name == domain || strings.HasSuffix(r.Name, "."+domain)
		}) || slices.ContainsFunc(excludeDomains, func(domain string) bool {
			return r.Name == domain || strings.HasSuffix(r.Name, "."+domain)
		}) {
			continue
		}
		switch r.Type {
		case "A":
			hostsEntries[r.Name] = r.Content
			if verbose {
				log.Printf("[A Record] %s -> %s", r.Name, r.Content)
			}
		case "CNAME":
			if ip, ok := recordIps[r.Name]; ok {
				hostsEntries[r.Name] = ip
				if verbose {
					log.Printf("[self-resolved CNAME Record] %s -> %s", r.Name, ip)
				}
			} else {
				cnameRecords = append(cnameRecords, r)
			}
		case "SRV":
			srvRecords = append(srvRecords, r)
		}
	}
	if verbose {
		log.Printf("Filtered records: %d A, %d CNAME, %d SRV", len(hostsEntries), len(cnameRecords), len(srvRecords))
	}

	// Process CNAME records (resolve them)
	var wg sync.WaitGroup
	var mu sync.Mutex // To safely write to hostsEntries from goroutines

	for _, r := range cnameRecords {
		wg.Add(1)
		go func(record cloudflare.DNSRecord) {
			defer wg.Done()
			if verbose {
				log.Printf("Resolving CNAME: %s -> %s", record.Name, record.Content)
			}
			// Attempt to resolve CNAME using Cloudflare's DNS (if possible via API)
			// or fallback to system DNS or a specific resolver.
			// For simplicity, this example uses system DNS.
			// A more robust solution might involve querying Cloudflare's public DNS (1.1.1.1) directly.
			ips, err := net.LookupIP(record.Content)
			if err != nil {
				log.Printf("Error resolving CNAME %s (%s): %v", record.Name, record.Content, err)
				mu.Lock()
				failedEntries[record.Name] = true
				mu.Unlock()
				return
			}
			if len(ips) > 0 {
				// Prefer IPv4 if available
				var chosenIP string
				for _, ip := range ips {
					if ip.To4() != nil {
						chosenIP = ip.String()
						break
					}
				}
				if chosenIP == "" {
					chosenIP = ips[0].String() // Fallback to the first IP (could be IPv6)
				}

				mu.Lock()
				hostsEntries[record.Name] = chosenIP
				mu.Unlock()
				if verbose {
					log.Printf("[CNAME Resolved] %s -> %s (%s)", record.Name, chosenIP, record.Content)
				}
			} else {
				log.Printf("Could not resolve CNAME %s (%s) to any IP address", record.Name, record.Content)
			}
		}(r)
	}
	wg.Wait() // Wait for all CNAME resolutions to complete

	if len(hostsEntries) > 0 {
		if err := updateHostsFile(hostsEntries, failedEntries); err != nil {
			log.Printf("Error updating hosts file: %v", err)
		}
	} else if verbose {
		log.Printf("No A or resolvable CNAME records found to update hosts file.")
	}

	// 6. Handle SRV Records (Save to ipset files)
	if saveSRVDir != "" && len(srvRecords) > 0 {
		if err := saveSRVRecords(srvRecords, recordIps); err != nil { // Pass API to resolve SRV targets if needed
			log.Printf("Error saving SRV records: %v", err)
		}
	} else if saveSRVDir != "" && verbose {
		log.Printf("No SRV records found to save or 'save-srv-dir' not provided.")
	}

	if dryRun {
		fmt.Printf("--- DRY RUN COMPLETED ---\n")
	} else {
		fmt.Printf("Program completed successfully.\n")
	}
}

// --- Helper Functions ---

func setupConfig() {
	// Environment variables take precedence
	cfToken = os.Getenv("CF_TOKEN")
	cfZone = os.Getenv("CF_ZONE")
	identifier = os.Getenv("IDENTIFIER")
	hostsFilePath = os.Getenv("HOSTS_FILE")
	domain = os.Getenv("DOMAIN")
	excludeDomain = os.Getenv("EXCLUDE_DOMAIN")
	saveSRVDir = os.Getenv("SAVE_SRV_DIR")

	// Command-line flags (can override env vars if desired, or just provide defaults)
	flag.StringVar(&cfToken, "cf-token", cfToken, "Cloudflare API Token (env: CF_TOKEN)")
	flag.StringVar(&cfZone, "cf-zone", cfZone, "Cloudflare Zone ID (env: CF_ZONE)")
	flag.StringVar(&domain, "domain", domain, "Base domain/subdomain (or multiple comma separated domains) to manage (e.g., example.com) (env: DOMAIN)")
	flag.StringVar(&excludeDomain, "exclude-domain", excludeDomain, "Exclude domain/subdomain (or multiple comma separated domains) from management (e.g., exclude.example.com) (env: EXCLUDE_DOMAIN)")
	flag.StringVar(&saveSRVDir, "save-srv-dir", saveSRVDir, "Directory to save SRV records for ipset (optional) (env: SAVE_SRV_DIR)")
	flag.StringVar(&identifier, "identifier", identifier, "Optional hosts file updating section identifier mark (env: IDENTIFIER)")
	flag.StringVar(&hostsFilePath, "hosts-file", hostsFilePath, `Hosts file path. If not provided, will use current OS system hosts file (env: HOSTS_FILE)`)
	flag.BoolVar(&dryRun, "dry-run", false, "If true, no actual changes will be made")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")

	flag.Parse()

	// Validations
	if cfToken == "" || cfZone == "" || domain == "" {
		log.Fatalf("Error: cf-token & cf-zone & domain must be provided.")
	}

	if hostsFilePath == "" {
		var err error
		hostsFilePath, err = getSystemHostsFilePath()
		if err != nil {
			log.Fatalf("Error getting hosts file path: %v", err)
		}
		if verbose {
			log.Printf("Using hosts file: %s", hostsFilePath)
		}
	}
	domain = strings.ToLower(domain)
}

func newCloudflareClient() (*cloudflare.API, error) {
	var api *cloudflare.API
	var err error

	if cfToken != "" {
		api, err = cloudflare.NewWithAPIToken(cfToken)
	} else {
		return nil, fmt.Errorf("insufficient Cloudflare API credentials provided")
	}

	if err != nil {
		return nil, err
	}
	// Optional: Set a custom HTTP client, User-Agent, etc.
	// api.SetUserAgent("my-cloudflare-dns-tool/1.0")
	return api, nil
}

func fetchDNSRecords(api *cloudflare.API) ([]cloudflare.DNSRecord, error) {
	// List all DNS records for the zone.
	// You might want to add pagination handling if you have a very large number of records.
	// For simplicity, this example fetches records matching common types.
	// You may need to adjust filtering based on your needs or fetch all and then filter.
	rc := &cloudflare.ResourceContainer{Level: cloudflare.ZoneRouteLevel, Identifier: cfZone}
	filter := cloudflare.ListDNSRecordsParams{
		Type: "A", // Initial fetch, can be expanded or fetched multiple times for different types
	}
	aRecords, _, err := api.ListDNSRecords(context.Background(), rc, filter)
	if err != nil {
		return nil, fmt.Errorf("fetching A records: %w", err)
	}

	filter.Type = "CNAME"
	cnameRecords, _, err := api.ListDNSRecords(context.Background(), rc, filter)
	if err != nil {
		return nil, fmt.Errorf("fetching CNAME records: %w", err)
	}

	filter.Type = "SRV"
	srvRecords, _, err := api.ListDNSRecords(context.Background(), rc, filter)
	if err != nil {
		return nil, fmt.Errorf("fetching SRV records: %w", err)
	}

	allRecords := append(aRecords, cnameRecords...)
	allRecords = append(allRecords, srvRecords...)

	// Alternative: Fetch all records and then filter in the Go program.
	// This might be simpler if the API doesn't support complex filtering by name suffix directly.
	// records, _, err := api.ListDNSRecords(context.Background(), rc, cloudflare.ListDNSRecordsParams{})
	// if err != nil {
	// 	return nil, err
	// }
	// return records, nil
	return allRecords, nil
}

func getSystemHostsFilePath() (string, error) {
	// OS-dependent hosts file path
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts"), nil
	case "linux", "darwin": // darwin is macOS
		return "/etc/hosts", nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func updateHostsFile(entries map[string]string, failedEntries map[string]bool) error {
	if verbose {
		log.Printf("Updating hosts file: %s", hostsFilePath)
	}

	// Read existing hosts file content
	file, err := os.OpenFile(hostsFilePath, os.O_RDWR|os.O_CREATE, 0644) // Read-write permissions
	if err != nil {
		return fmt.Errorf("could not open hosts file %q (run with sudo?): %w", hostsFilePath, err)
	}
	defer file.Close()

	var newLines []string
	scanner := bufio.NewScanner(file)
	inManagedBlock := false

	delimiter := HOSTS_FILE_DELIMITER_PREFIX
	if identifier != "" {
		delimiter += "_" + strings.ToUpper(identifier)
	}
	hostsFileStartDelimiter := delimiter + "_START"
	hostsFileEndDelimiter := delimiter + "_END"

	var existingRecordLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == hostsFileStartDelimiter {
			inManagedBlock = true
			// Skip lines within our managed block, they will be re-added
			continue
		}
		if strings.TrimSpace(line) == hostsFileEndDelimiter {
			inManagedBlock = false
			continue
		}
		if !inManagedBlock {
			newLines = append(newLines, line)
		} else {
			existingRecordLines = append(existingRecordLines, line)
			ip, domain, _ := strings.Cut(strings.TrimSpace(line), " ")
			if ip != "" && domain != "" && failedEntries[domain] {
				// for failed (cname) entries, keep existing (if any) lines unchanged
				entries[domain] = ip
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading hosts file: %w", err)
	}

	domains := []string{}
	for domain := range entries {
		domains = append(domains, domain)
	}
	slices.Sort(domains)

	var newRecordLines []string
	for _, domain := range domains {
		ip := entries[domain]
		newRecordLines = append(newRecordLines, fmt.Sprintf("%s %s", ip, domain))
	}
	if slices.Equal(existingRecordLines, newRecordLines) {
		log.Printf("Same contents as existing hosts file, no need to update")
		return nil
	}

	if dryRun {
		fmt.Printf("[Dry Run] Would update hosts file with the following entries:\n")
		fmt.Printf("---\n")
		for _, line := range newRecordLines {
			fmt.Printf("%s\n", line)
		}
		fmt.Printf("---\n")
		return nil
	}

	// Add our managed block
	newLines = append(newLines, hostsFileStartDelimiter)
	newLines = append(newLines, newRecordLines...)
	newLines = append(newLines, hostsFileEndDelimiter)

	// Write back to the hosts file
	// Need to truncate the file first before writing new content
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("could not truncate hosts file: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("could not seek to beginning of hosts file: %w", err)
	}

	writer := bufio.NewWriter(file)
	for _, line := range newLines {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return fmt.Errorf("error writing to hosts file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing writer for hosts file: %w", err)
	}

	log.Printf("Hosts file %q updated successfully.", hostsFilePath)
	return nil
}

// resolveSRVTarget resolves the target of an SRV record to IP addresses.
// This is necessary because SRV records point to hostnames, not directly to IPs.
// The returned resolved ip list is in order, the earlier the higher the priority.
func resolveSRVTarget(targetHostname string, recordIps map[string]string) ([]string, error) {
	var ips []string
	if verbose {
		log.Printf("Resolving SRV target: %s\n", targetHostname)
	}
	if ip, ok := recordIps[targetHostname]; ok {
		ips = append(ips, ip)
		if verbose {
			log.Printf("Resolved SRV target %s to %s (via same zone records)", targetHostname, ip)
		}
	} else if resolvedIPs, err := net.LookupIP(targetHostname); err == nil {
		for _, ip := range resolvedIPs {
			ips = append(ips, ip.String())
			if verbose {
				log.Printf("Resolved SRV target %s to %s (via net.LookupIP)", targetHostname, ip.String())
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for SRV target hostname %q", targetHostname)
	}
	return ips, nil
}

func saveSRVRecords(records []cloudflare.DNSRecord, recordIps map[string]string) error {
	if saveSRVDir == "" {
		return nil // Nothing to do
	}

	if verbose {
		log.Printf("Processing %d SRV records for directory: %s", len(records), saveSRVDir)
	}

	if _, err := os.Stat(saveSRVDir); os.IsNotExist(err) {
		return fmt.Errorf("SRV save directory %q dones not exist: %w", saveSRVDir, err)
	}

	// Group SRV records by service name
	// _service._proto.name -> SRV record data (Target, Port, Priority, Weight)
	// Filename will be "service"
	srvDataByService := make(map[string][]string) // service_name -> []"ip,port"

	srvRegex := regexp.MustCompile(`^_([^\.]+)\._([^\.]+)\.(.*)`) // Matches _service._proto.domain

	for _, r := range records {
		if r.Type != "SRV" || r.Data == nil {
			continue
		}
		// port,priority,weight,target. target is string while others are float64
		data, ok := r.Data.(map[string]any)
		if !ok {
			log.Printf("Invalid srv data format")
			continue
		}
		log.Printf("srv data: %v", data)
		targetHost := util.ToString(data["target"])
		port := util.ToInt(data["port"])
		if targetHost == "" || port == 0 {
			log.Printf("Invalid srv target %q or port %d", targetHost, port)
			continue
		}

		// r.Name is like _service._tcp.example.com
		// r.SRVData.Target is the actual hostname providing the service
		// r.SRVData.Port is the port number
		matches := srvRegex.FindStringSubmatch(r.Name)
		if len(matches) < 2 {
			log.Printf("Could not parse service name from SRV record: %s", r.Name)
			continue
		}
		serviceName := matches[1] // e.g., "sip" from "_sip._tcp.example.com"
		proto := matches[2]       // e.g. "tcp"

		if verbose {
			log.Printf("[SRV Record] %s -> Target: %s, Proto: %s, Port: %d", r.Name, targetHost, proto, port)
		}

		// Resolve the SRV target to an IP address(es)
		// This is crucial as SRV records point to hostnames.
		targetIPs, err := resolveSRVTarget(targetHost, recordIps)
		if err != nil {
			log.Printf("Error resolving SRV target %q for service %q: %v", targetHost, serviceName, err)
			continue // Skip this record if target cannot be resolved
		}

		for _, ip := range targetIPs {
			// Ensure it's an IPv4 address for ipset hash:ip,port (ipset can handle IPv6 with hash:ip6,port)
			// For simplicity, we'll focus on IPv4 here.
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() != nil {
				srvDataByService[serviceName] = append(srvDataByService[serviceName], fmt.Sprintf("%s,%s:%d", ip, proto, port))
			} else if parsedIP != nil && parsedIP.To16() != nil && parsedIP.To4() == nil {
				// Could also handle IPv6 if ipset type is hash:ip6,port
				if verbose {
					log.Printf("SRV target %s resolved to IPv6 %s, skipping for hash:ip,port ipset type.", targetHost, ip)
				}
			} else {
				if verbose {
					log.Printf("SRV target %s resolved to %q which is not a valid IP, skipping.", targetHost, ip)
				}
			}
		}
	}

	for service, entries := range srvDataByService {
		if len(entries) == 0 {
			continue
		}

		fileName := filepath.Join(saveSRVDir, service+".ipset") // Use "service" as filename
		ipsetFileContent := ""
		for _, entry := range entries {
			ipsetFileContent += fmt.Sprintf("%s\n", entry)
		}

		if existingContents, err := os.ReadFile(fileName); err == nil {
			if string(existingContents) == ipsetFileContent {
				log.Printf("Same contents as existing ipset file %q, no need to update", fileName)
				continue
			}
		}

		if dryRun {
			fmt.Printf("[Dry Run] Would write to SRV ipset file %q:\n", fileName)
			fmt.Printf("---\n")
			fmt.Printf("%s\n", strings.TrimSpace(ipsetFileContent))
			fmt.Printf("---\n")
			continue
		}

		err := os.WriteFile(fileName, []byte(ipsetFileContent), 0644)
		if err != nil {
			log.Printf("Error writing SRV ipset file %q: %v", fileName, err)
		} else {
			log.Printf("SRV ipset data saved to: %s\n", fileName)
		}
	}
	return nil
}

// Extract all domain => ip records from CloudFlare DNS records.
// Consider only A / AAAA & CNAME records.
// For A / AAAA record, use it's ip content.
// For CNAME records, if the target name itself exists in records as a A / CNAME, use the resolved ip.
// If the final cname target name doesn't exist in records, ignore it.
func resolveIps(records []cloudflare.DNSRecord) map[string]string {
	result := make(map[string]string)
	cnameTargets := make(map[string]string)

	for _, record := range records {
		switch record.Type {
		case "A", "AAAA":
			result[record.Name] = record.Content
		case "CNAME":
			cnameTargets[record.Name] = record.Content
		}
	}

outer:
	for name, target := range cnameTargets {
		for range 3 {
			if ip, ok := result[target]; ok {
				result[name] = ip
				continue outer
			}
			if nextTarget, ok := cnameTargets[target]; ok {
				target = nextTarget
			} else {
				continue outer
			}
		}
	}

	return result
}
