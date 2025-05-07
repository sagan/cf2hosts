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
)

const VERSION = "v0.1.0"

// --- Configuration Variables ---
var (
	cfAPIToken string
	cfZoneID   string
	domain     string
	saveSRVDir string
	identifier string
	dryRun     bool
	verbose    bool // Optional: for more detailed output
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
		fmt.Println("--- DRY RUN MODE ENABLED ---")
	}
	if verbose {
		fmt.Println("Verbose mode enabled.")
	}

	// 2. Initialize Cloudflare API Client
	api, err := newCloudflareClient()
	if err != nil {
		logError("Error creating Cloudflare client: %v", err)
		os.Exit(1)
	}

	// 3. Fetch DNS Records
	if verbose {
		fmt.Printf("Fetching DNS records for zone ID '%s' and domain '%s'...\n", cfZoneID, domain)
	}
	records, err := fetchDNSRecords(api)
	if err != nil {
		logError("Error fetching DNS records: %v", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Found %d DNS records.\n", len(records))
	}

	// 4. Process Records
	var aRecords []cloudflare.DNSRecord
	var cnameRecords []cloudflare.DNSRecord
	var srvRecords []cloudflare.DNSRecord

	domains := strings.Split(domain, ",")

	for _, r := range records {
		r.Name = strings.ToLower(r.Name)
		// Filter for the specific domain or subdomains
		if slices.ContainsFunc(domains, func(domain string) bool {
			if !strings.HasPrefix(domain, ".") {
				domain = "." + domain
			}
			return strings.HasSuffix(r.Name, domain)
		}) {
			switch r.Type {
			case "A":
				aRecords = append(aRecords, r)
			case "CNAME":
				cnameRecords = append(cnameRecords, r)
			case "SRV":
				srvRecords = append(srvRecords, r)
			}
		}
	}

	if verbose {
		fmt.Printf("Filtered records: %d A, %d CNAME, %d SRV\n", len(aRecords), len(cnameRecords), len(srvRecords))
	}

	// 5. Handle A and CNAME Records (Update Hosts File)
	hostsEntries := make(map[string]string) // domain -> ip
	failedEntries := make(map[string]bool)

	// Process A records
	for _, r := range aRecords {
		hostsEntries[r.Name] = r.Content
		if verbose {
			fmt.Printf("  [A Record] %s -> %s\n", r.Name, r.Content)
		}
	}

	// Process CNAME records (resolve them)
	var wg sync.WaitGroup
	var mu sync.Mutex // To safely write to hostsEntries from goroutines

	for _, r := range cnameRecords {
		wg.Add(1)
		go func(record cloudflare.DNSRecord) {
			defer wg.Done()
			if verbose {
				fmt.Printf("  Resolving CNAME: %s -> %s\n", record.Name, record.Content)
			}
			// Attempt to resolve CNAME using Cloudflare's DNS (if possible via API)
			// or fallback to system DNS or a specific resolver.
			// For simplicity, this example uses system DNS.
			// A more robust solution might involve querying Cloudflare's public DNS (1.1.1.1) directly.
			ips, err := net.LookupIP(record.Content)
			if err != nil {
				logError("  Error resolving CNAME %s (%s): %v", record.Name, record.Content, err)
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
					fmt.Printf("  [CNAME Resolved] %s -> %s (%s)\n", record.Name, chosenIP, record.Content)
				}
			} else {
				logError("  Could not resolve CNAME %s (%s) to any IP address", record.Name, record.Content)
			}
		}(r)
	}
	wg.Wait() // Wait for all CNAME resolutions to complete

	if len(hostsEntries) > 0 {
		if err := updateHostsFile(hostsEntries, failedEntries); err != nil {
			logError("Error updating hosts file: %v", err)
		}
	} else if verbose {
		fmt.Println("No A or resolvable CNAME records found to update hosts file.")
	}

	// 6. Handle SRV Records (Save to ipset files)
	if saveSRVDir != "" && len(srvRecords) > 0 {
		if err := saveSRVRecords(srvRecords, api); err != nil { // Pass API to resolve SRV targets if needed
			logError("Error saving SRV records: %v", err)
		}
	} else if saveSRVDir != "" && verbose {
		fmt.Println("No SRV records found to save or 'save-srv-dir' not provided.")
	}

	if dryRun {
		fmt.Println("--- DRY RUN COMPLETED ---")
	} else {
		fmt.Println("Program completed successfully.")
	}
}

// --- Helper Functions ---

func setupConfig() {
	// Environment variables take precedence
	cfAPIToken = os.Getenv("CLOUDFLARE_API_TOKEN")
	cfZoneID = os.Getenv("CLOUDFLARE_ZONE_ID")
	identifier = os.Getenv("IDENTIFIER")
	domain = os.Getenv("CLOUDFLARE_DOMAIN")
	saveSRVDir = os.Getenv("SAVE_SRV_DIR")

	// Command-line flags (can override env vars if desired, or just provide defaults)
	flag.StringVar(&cfAPIToken, "cf-token", cfAPIToken, "Cloudflare API Token (env: CLOUDFLARE_API_TOKEN)")
	flag.StringVar(&cfZoneID, "zone-id", cfZoneID, "Cloudflare Zone ID (env: CLOUDFLARE_ZONE_ID)")
	flag.StringVar(&domain, "domain", domain, "Base domain/subdomain (or multiple comma separated domains) to manage (e.g., example.com) (env: CLOUDFLARE_DOMAIN)")
	flag.StringVar(&saveSRVDir, "save-srv-dir", saveSRVDir, "Directory to save SRV records for ipset (optional) (env: SAVE_SRV_DIR)")
	flag.StringVar(&identifier, "identifier", "", "Optional hosts file updating section identifier mark")
	flag.BoolVar(&dryRun, "dry-run", false, "If true, no actual changes will be made")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")

	flag.Parse()

	// Validations
	if cfAPIToken == "" {
		logError("Error: Cloudflare API Token must be provided.")
		flag.Usage()
		os.Exit(1)
	}
	if cfZoneID == "" {
		logError("Error: Cloudflare Zone ID must be provided.")
		flag.Usage()
		os.Exit(1)
	}
	if domain == "" {
		logError("Error: Domain must be provided.")
		flag.Usage()
		os.Exit(1)
	}
	domain = strings.ToLower(domain)
}

func newCloudflareClient() (*cloudflare.API, error) {
	var api *cloudflare.API
	var err error

	if cfAPIToken != "" {
		api, err = cloudflare.NewWithAPIToken(cfAPIToken)
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
	rc := &cloudflare.ResourceContainer{Level: cloudflare.ZoneRouteLevel, Identifier: cfZoneID}
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

func getHostsFilePath() (string, error) {
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
	hostsFilePath, err := getHostsFilePath()
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("Updating hosts file: %s\n", hostsFilePath)
	}

	// Read existing hosts file content
	file, err := os.OpenFile(hostsFilePath, os.O_RDWR, 0644) // Read-write permissions
	if err != nil {
		return fmt.Errorf("could not open hosts file '%s' (run with sudo?): %w", hostsFilePath, err)
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
		fmt.Printf("Same contents as existing hosts file section, no need to update\n")
		return nil
	}

	if dryRun {
		fmt.Printf("  [Dry Run] Would update hosts file with the following entries:\n")
		for _, line := range newRecordLines {
			fmt.Printf("%s\n", line)
		}
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

	fmt.Printf("Hosts file '%s' updated successfully.\n", hostsFilePath)
	return nil
}

// resolveSRVTarget resolves the target of an SRV record to IP addresses.
// This is necessary because SRV records point to hostnames, not directly to IPs.
func resolveSRVTarget(targetHostname string, api *cloudflare.API, zoneID string) ([]string, error) {
	var ips []string

	// 1. Check if the target is an A/AAAA record within the same Cloudflare zone
	// This part is a bit tricky as it requires another API call to find the A/AAAA record.
	// We'll simplify by trying direct DNS lookup first, but a more robust CF-centric
	// solution would query CF DNS records for the target.

	// For now, we'll use net.LookupIP. A more advanced version could:
	// a) Query Cloudflare for A/AAAA records matching targetHostname within the zoneID
	// b) Use Cloudflare's 1.1.1.1 resolver for external domains

	if verbose {
		fmt.Printf("    Resolving SRV target: %s\n", targetHostname)
	}

	resolvedIPs, err := net.LookupIP(targetHostname)
	if err != nil {
		// Fallback or specific error handling if needed
		// Try to see if it's a record within our managed domain and we already resolved it.
		// This is a simplification; a full CF lookup would be better.
		rc := &cloudflare.ResourceContainer{Level: cloudflare.ZoneRouteLevel, Identifier: zoneID}
		filter := cloudflare.ListDNSRecordsParams{Name: targetHostname}
		targetRecords, _, listErr := api.ListDNSRecords(context.Background(), rc, filter)
		if listErr == nil {
			for _, rec := range targetRecords {
				if rec.Type == "A" || rec.Type == "AAAA" {
					ips = append(ips, rec.Content)
					if verbose {
						fmt.Printf("      Resolved SRV target %s to %s (via CF record)\n", targetHostname, rec.Content)
					}
				}
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("could not resolve SRV target hostname '%s': %w", targetHostname, err)
		}
	} else {
		for _, ip := range resolvedIPs {
			ips = append(ips, ip.String())
			if verbose {
				fmt.Printf("      Resolved SRV target %s to %s (via net.LookupIP)\n", targetHostname, ip.String())
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for SRV target hostname '%s'", targetHostname)
	}
	return ips, nil
}

func saveSRVRecords(records []cloudflare.DNSRecord, cfApi *cloudflare.API) error {
	if saveSRVDir == "" {
		return nil // Nothing to do
	}

	if verbose {
		fmt.Printf("Processing SRV records for directory: %s\n", saveSRVDir)
	}

	if _, err := os.Stat(saveSRVDir); os.IsNotExist(err) {
		if !dryRun {
			if err := os.MkdirAll(saveSRVDir, 0755); err != nil {
				return fmt.Errorf("could not create SRV save directory '%s': %w", saveSRVDir, err)
			}
			fmt.Printf("Created directory: %s\n", saveSRVDir)
		} else {
			fmt.Printf("  [Dry Run] Would create directory: %s\n", saveSRVDir)
		}
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

		log.Printf("srv data: %v", r.Data)

		// r.Name is like _service._tcp.example.com
		// r.SRVData.Target is the actual hostname providing the service
		// r.SRVData.Port is the port number
		matches := srvRegex.FindStringSubmatch(r.Name)
		if len(matches) < 2 {
			logError("  Could not parse service name from SRV record: %s", r.Name)
			continue
		}
		serviceName := matches[1] // e.g., "sip" from "_sip._tcp.example.com"
		targetHost := ""          // r.SRVData.Target
		port := 21                //   r.SRVData.Port

		if verbose {
			fmt.Printf("  [SRV Record] %s -> Target: %s, Port: %d\n", r.Name, targetHost, port)
		}

		// Resolve the SRV target to an IP address(es)
		// This is crucial as SRV records point to hostnames.
		targetIPs, err := resolveSRVTarget(targetHost, cfApi, cfZoneID)
		if err != nil {
			logError("  Error resolving SRV target '%s' for service '%s': %v", targetHost, serviceName, err)
			continue // Skip this record if target cannot be resolved
		}

		for _, ip := range targetIPs {
			// Ensure it's an IPv4 address for ipset hash:ip,port (ipset can handle IPv6 with hash:ip6,port)
			// For simplicity, we'll focus on IPv4 here.
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() != nil {
				srvDataByService[serviceName] = append(srvDataByService[serviceName], fmt.Sprintf("%s,%d", ip, port))
			} else if parsedIP != nil && parsedIP.To16() != nil && parsedIP.To4() == nil {
				// Could also handle IPv6 if ipset type is hash:ip6,port
				if verbose {
					fmt.Printf("    SRV target %s resolved to IPv6 %s, skipping for hash:ip,port ipset type.\n", targetHost, ip)
				}
			} else {
				if verbose {
					fmt.Printf("    SRV target %s resolved to '%s' which is not a valid IP, skipping.\n", targetHost, ip)
				}
			}
		}
	}

	for service, entries := range srvDataByService {
		if len(entries) == 0 {
			continue
		}
		fileName := filepath.Join(saveSRVDir, service)                                                          // Use "service" as filename
		ipsetFileContent := "create " + service + "_set hash:ip,port family inet hashsize 1024 maxelem 65536\n" // Example header
		// Or, if the set is assumed to exist:
		// ipsetFileContent := ""

		for _, entry := range entries {
			ipsetFileContent += fmt.Sprintf("add %s_set %s\n", service, entry)
		}

		if dryRun {
			fmt.Printf("  [Dry Run] Would write to SRV file '%s':\n", fileName)
			fmt.Println(strings.TrimSpace(ipsetFileContent))
			fmt.Println("---")
			continue
		}

		err := os.WriteFile(fileName, []byte(ipsetFileContent), 0644)
		if err != nil {
			logError("  Error writing SRV ipset file '%s': %v", fileName, err)
		} else {
			fmt.Printf("  SRV ipset data saved to: %s\n", fileName)
		}
	}
	return nil
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}

// --- Entry Point ---
// (main function is above)
