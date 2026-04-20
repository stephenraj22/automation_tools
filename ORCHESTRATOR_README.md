# Security Automation Orchestrator

A unified tool to orchestrate all security testing modules and generate consolidated reports.

## Features

- **Automated Orchestration**: Runs all security tools with a single command
- **Dependency Management**: Automatically handles tool dependencies and execution order
- **Comprehensive Coverage**: Includes directory traversal, insecure configuration, subdomain takeover, RCE, SQLi, and reconnaissance
- **Unified Reporting**: Generates HTML and JSON reports with executive summaries
- **Simple Interface**: Easy-to-use command-line interface
- **Error Handling**: Graceful handling of timeouts and errors

## Tools Included (Execution Order)

The orchestrator runs tools in dependency order:

1. **Reconnaissance (js_analysis.sh)** - Runs first to generate input files
   - Generates: domains, URLs, JavaScript files, JSON files, TXT files
   - Required by: directory_traversal, insecure_configuration, subdomain_takeover, sqli

2. **Directory Traversal Scanner** - Tests for path traversal vulnerabilities
   - Requires: domains file from reconnaissance

3. **Insecure Configuration Scanner** - Detects exposed sensitive keys and configurations
   - Requires: JavaScript files from reconnaissance

4. **Subdomain Takeover Scanner** - Identifies vulnerable subdomains
   - Requires: domains file from reconnaissance

5. **RCE Scanner** - Tests for remote code execution vulnerabilities
   - Independent (no dependencies)

6. **SQL Injection Scanner** - Detects SQL injection points
   - Requires: domains file from reconnaissance

## Usage

### Simple Command (Windows)
```batch
run_scan.bat example.com
```

### Python Script
```bash
python orchestrator.py example.com
```

### Advanced Options

Run all tools:
```bash
python orchestrator.py example.com --all
```

Run specific tools:
```bash
python orchestrator.py example.com --tools directory_traversal,insecure_configuration
```

Specify output directory:
```bash
python orchestrator.py example.com --output /path/to/output
```

## Output

The orchestrator generates two types of reports:

1. **HTML Report** - Human-readable report with:
   - Executive summary
   - Detailed tool results
   - Status indicators (completed/failed/timeout/error)
   - Recommendations

2. **JSON Report** - Machine-readable report for automation

Reports are saved in the output directory with timestamps.

## Requirements

- Python 3.7+
- All individual security tools must be properly installed
- Required external tools: bash, subfinder, httprobe, nmap, aws cli, sqlmap, commix, gau, httpx

## Example Workflow

```bash
# Run full security assessment
python orchestrator.py target.com

# View the generated HTML report
# Report location: /mnt/target.com/security_report_target.com_YYYYMMDD_HHMMSS.html
```

## Notes

- The orchestrator automatically creates necessary input files if they don't exist
- Each tool runs with a 10-minute timeout
- Failed scans are logged in the report for review
- Tool outputs are truncated in the report for readability
