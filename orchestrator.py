#!/usr/bin/env python3
"""
Security Automation Orchestrator
Runs all security testing tools and generates a consolidated report.
Usage: python orchestrator.py <domain> [--all] [--tools TOOL1,TOOL2,...]
"""

import argparse
import subprocess
import os
import sys
import json
import csv
from datetime import datetime
from pathlib import Path
import threading
import time

class SecurityOrchestrator:
    def __init__(self, domain, output_dir=None, scope_file=None, rate_limit=1, check_alive=False):
        self.domain = domain
        self.base_dir = Path(__file__).parent
        # Use /mnt/{domain} as default output directory
        self.output_dir = Path(output_dir) if output_dir else Path(f"/mnt/{domain}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        # Rate limiting (delay in seconds between requests)
        self.rate_limit = rate_limit
        # Scope management
        self.scope = self.load_scope(scope_file) if scope_file else None
        # Alive check option
        self.check_alive = check_alive
        # Tools in dependency order - recon must run first to generate input files
        self.tools = {
            'recon': self.run_js_analysis,  # Generates domains, urls, js, json, txt files
            'alive_check': self.run_alive_check,  # Filters dead endpoints (optional)
            'directory_traversal': self.run_directory_traversal,  # Depends on domains file
            'insecure_configuration': self.run_insecure_configuration,  # Depends on js file
            'subdomain_takeover': self.run_subdomain_takeover,  # Depends on domains file
            'rce': self.run_rce,  # Independent
            'sqli': self.run_sqli  # Depends on domains file
        }
    
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def load_scope(self, scope_file):
        """Load scope from file (include and exclude domains)"""
        scope = {'include': [], 'exclude': []}
        try:
            with open(scope_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line.startswith('!'):
                            scope['exclude'].append(line[1:])
                        else:
                            scope['include'].append(line)
            self.log(f"Loaded scope: {len(scope['include'])} include, {len(scope['exclude'])} exclude")
        except Exception as e:
            self.log(f"Error loading scope file: {e}")
        return scope
    
    def is_in_scope(self, domain):
        """Check if domain is in scope"""
        if not self.scope:
            return True
        
        # Check exclude first
        for exclude in self.scope['exclude']:
            if exclude in domain:
                return False
        
        # Check include
        if self.scope['include']:
            for include in self.scope['include']:
                if include in domain:
                    return True
            return False
        
        return True
    
    def run_alive_check(self):
        """Run alive check on domains to filter out dead endpoints"""
        self.log("Running Alive Check on domains...")
        script_path = self.base_dir / "utils/alive_check.py"
        
        domains_file = self.output_dir / f"domains_{self.domain}.txt"
        alive_domains_file = self.output_dir / f"alive_domains_{self.domain}.txt"
        
        if not script_path.exists():
            self.log("alive_check.py not found, skipping alive check")
            return False
        
        if not domains_file.exists():
            self.log(f"Domains file not found: {domains_file}")
            return False
        
        try:
            result = subprocess.run(
                [sys.executable, str(script_path), str(domains_file), str(alive_domains_file), "10", "5"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.log(f"Alive check completed. Results saved to {alive_domains_file}")
                # Replace domains file with alive domains
                if alive_domains_file.exists():
                    import shutil
                    shutil.copy(alive_domains_file, domains_file)
                return True
            else:
                self.log(f"Alive check failed: {result.stderr}")
                return False
        except Exception as e:
            self.log(f"Alive check error: {e}")
            return False
    
    def run_js_analysis(self):
        """Run JS analysis/reconnaissance to generate input files for other tools"""
        self.log("Running JS Analysis/Reconnaissance (generating input files)...")
        script_path = self.base_dir / "recon/js_analysis.sh"
        
        if not script_path.exists():
            self.results['recon'] = {'status': 'skipped', 'error': 'js_analysis.sh not found'}
            self.log("js_analysis.sh not found, skipping reconnaissance")
            return
        
        try:
            env = os.environ.copy()
            env['OUTPUT_DIR'] = str(self.output_dir)
            result = subprocess.run(
                ["bash", str(script_path), self.domain],
                capture_output=True,
                text=True,
                env=env
            )
            self.results['recon'] = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr
            }
            
            # Verify required files were generated
            required_files = [
                self.output_dir / f"domains_{self.domain}.txt",
                self.output_dir / f"js_{self.domain}.txt"
            ]
            
            missing_files = [f for f in required_files if not f.exists()]
            if missing_files:
                self.log(f"Warning: Some required files were not generated: {missing_files}")
                self.results['recon']['status'] = 'partial'
                self.results['recon']['missing_files'] = [str(f) for f in missing_files]
            
            self.log("Reconnaissance completed")
            
            # Rate limiting delay
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
        except Exception as e:
            self.results['recon'] = {'status': 'error', 'error': str(e)}
            self.log(f"Reconnaissance error: {e}")
    
    def run_directory_traversal(self):
        """Run directory traversal vulnerability scanner"""
        self.log("Running Directory Traversal Scanner...")
        script_path = self.base_dir / "directory_traversal/python_script/v1/directory_traversal.py"
        
        # Check if required input file exists (should be generated by recon)
        domains_file = self.output_dir / f"domains_{self.domain}.txt"
        if not domains_file.exists():
            self.results['directory_traversal'] = {'status': 'skipped', 'error': f'Required file not found: {domains_file}. Run recon first.'}
            self.log(f"Skipping Directory Traversal: Required file {domains_file} not found")
            return
        
        try:
            env = os.environ.copy()
            env['OUTPUT_DIR'] = str(self.output_dir)
            result = subprocess.run(
                [sys.executable, str(script_path), self.domain],
                capture_output=True,
                text=True,
                env=env
            )
            self.results['directory_traversal'] = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr
            }
            self.log(f"Directory Traversal scan completed")
            
            # Rate limiting delay
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
        except Exception as e:
            self.results['directory_traversal'] = {'status': 'error', 'error': str(e)}
            self.log(f"Directory Traversal scan error: {e}")
    
    def run_insecure_configuration(self):
        """Run insecure configuration scanner with improved API key detection"""
        self.log("Running Insecure Configuration Scanner (v3 with regex patterns)...")
        script_path = self.base_dir / "insecure_configuration/python_script/v3/search_insecure_configuration.py"
        
        # Check if required input file exists (should be generated by recon)
        js_file = self.output_dir / f"js_{self.domain}.txt"
        if not js_file.exists():
            self.results['insecure_configuration'] = {'status': 'skipped', 'error': f'Required file not found: {js_file}. Run recon first.'}
            self.log(f"Skipping Insecure Configuration: Required file {js_file} not found")
            return
        
        try:
            env = os.environ.copy()
            env['OUTPUT_DIR'] = str(self.output_dir)
            result = subprocess.run(
                [sys.executable, str(script_path), self.domain],
                capture_output=True,
                text=True,
                env=env
            )
            self.results['insecure_configuration'] = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr
            }
            self.log("Insecure Configuration scan completed")
            
            # Rate limiting delay
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
        except Exception as e:
            self.results['insecure_configuration'] = {'status': 'error', 'error': str(e)}
            self.log(f"Insecure Configuration scan error: {e}")
    
    def run_subdomain_takeover(self):
        """Run subdomain takeover scanner"""
        self.log("Running Subdomain Takeover Scanner...")
        script_path = self.base_dir / "subdomain_takeover/subdomain_takeover.py"
        
        # Use domains file generated by recon
        domains_file = self.output_dir / f"domains_{self.domain}.txt"
        if not domains_file.exists():
            self.results['subdomain_takeover'] = {'status': 'skipped', 'error': f'Required file not found: {domains_file}. Run recon first.'}
            self.log(f"Skipping Subdomain Takeover: Required file {domains_file} not found")
            return
        
        try:
            env = os.environ.copy()
            env['OUTPUT_DIR'] = str(self.output_dir)
            result = subprocess.run(
                [sys.executable, str(script_path), "-f", str(domains_file), "-d", self.domain],
                capture_output=True,
                text=True,
                env=env
            )
            self.results['subdomain_takeover'] = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr
            }
            self.log("Subdomain Takeover scan completed")
            
            # Rate limiting delay
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
        except Exception as e:
            self.results['subdomain_takeover'] = {'status': 'error', 'error': str(e)}
            self.log(f"Subdomain Takeover scan error: {e}")
    
    def run_rce(self):
        """Run RCE vulnerability scanner"""
        self.log("Running RCE Scanner...")
        script_path = self.base_dir / "rce/shell_script/rce.sh"
        
        if not script_path.exists():
            self.results['rce'] = {'status': 'skipped', 'error': 'Script not found'}
            self.log("RCE script not found, skipping")
            return
        
        target_url = f"https://{self.domain}"
        
        try:
            result = subprocess.run(
                ["bash", str(script_path), target_url],
                capture_output=True,
                text=True,
                cwd=str(self.output_dir)
            )
            self.results['rce'] = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr
            }
            self.log("RCE scan completed")
            
            # Rate limiting delay
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
        except Exception as e:
            self.results['rce'] = {'status': 'error', 'error': str(e)}
            self.log(f"RCE scan error: {e}")
    
    def run_sqli(self):
        """Run SQL Injection scanner"""
        self.log("Running SQL Injection Scanner...")
        script_path = self.base_dir / "sqli/shell_script/v1/sqli.sh"
        
        if not script_path.exists():
            self.results['sqli'] = {'status': 'skipped', 'error': 'Script not found'}
            self.log("SQLi script not found, skipping")
            return
        
        # Check if required input file exists (should be generated by recon)
        domains_file = self.output_dir / f"domains_{self.domain}.txt"
        if not domains_file.exists():
            self.results['sqli'] = {'status': 'skipped', 'error': f'Required file not found: {domains_file}. Run recon first.'}
            self.log(f"Skipping SQL Injection: Required file {domains_file} not found")
            return
        
        try:
            env = os.environ.copy()
            env['OUTPUT_DIR'] = str(self.output_dir)
            result = subprocess.run(
                ["bash", str(script_path), self.domain],
                capture_output=True,
                text=True,
                env=env
            )
            self.results['sqli'] = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr
            }
            self.log("SQL Injection scan completed")
            
            # Rate limiting delay
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
        except Exception as e:
            self.results['sqli'] = {'status': 'error', 'error': str(e)}
            self.log(f"SQL Injection scan error: {e}")
    
    def generate_report(self):
        """Generate consolidated report"""
        self.log("Generating consolidated report...")
        
        report_file = self.output_dir / f"security_report_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {self.domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        .summary {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .tool-section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .tool-section.completed {{ border-left: 5px solid #4CAF50; }}
        .tool-section.partial {{ border-left: 5px solid #2196F3; }}
        .tool-section.failed {{ border-left: 5px solid #f44336; }}
        .tool-section.timeout {{ border-left: 5px solid #ff9800; }}
        .tool-section.error {{ border-left: 5px solid #9c27b0; }}
        .tool-section.skipped {{ border-left: 5px solid #9e9e9e; }}
        .status {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; }}
        .status.completed {{ background: #4CAF50; color: white; }}
        .status.partial {{ background: #2196F3; color: white; }}
        .status.failed {{ background: #f44336; color: white; }}
        .status.timeout {{ background: #ff9800; color: white; }}
        .status.error {{ background: #9c27b0; color: white; }}
        .status.skipped {{ background: #9e9e9e; color: white; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {self.domain}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>Total tools executed: {len(self.results)}</p>
            <p>Successful: {sum(1 for r in self.results.values() if r['status'] == 'completed')}</p>
            <p>Partial: {sum(1 for r in self.results.values() if r['status'] == 'partial')}</p>
            <p>Failed: {sum(1 for r in self.results.values() if r['status'] == 'failed')}</p>
            <p>Timeouts: {sum(1 for r in self.results.values() if r['status'] == 'timeout')}</p>
            <p>Errors: {sum(1 for r in self.results.values() if r['status'] == 'error')}</p>
            <p>Skipped: {sum(1 for r in self.results.values() if r['status'] == 'skipped')}</p>
        </div>
        
        <h2>Detailed Results</h2>
"""
        
        for tool_name, result in self.results.items():
            html_content += f"""
        <div class="tool-section {result['status']}">
            <h3>{tool_name.replace('_', ' ').title()}</h3>
            <p><span class="status {result['status']}">{result['status'].upper()}</span></p>
"""
            if result.get('output'):
                html_content += f"            <h4>Output:</h4>\n            <pre>{result['output'][:1000]}</pre>\n"
            if result.get('error') and result['status'] != 'completed':
                html_content += f"            <h4>Error:</h4>\n            <pre>{result['error'][:1000]}</pre>\n"
            html_content += "        </div>\n"
        
        html_content += """
        <h2>Recommendations</h2>
        <ul>
            <li>Review all failed and timeout scans for potential issues</li>
            <li>Investigate any vulnerabilities found by the scanners</li>
            <li>Ensure all tools are properly installed and configured</li>
            <li>Run regular security assessments to maintain security posture</li>
        </ul>
        
        <p class="timestamp">Report generated by Security Automation Orchestrator</p>
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        # Also save JSON report
        json_file = report_file.with_suffix('.json')
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.log(f"Report generated: {report_file}")
        self.log(f"JSON report generated: {json_file}")
        
        return report_file
    
    def run(self):
        """Run all tools in dependency order"""
        self.log(f"Starting security assessment for {self.domain}")
        self.log(f"Output directory: {self.output_dir}")
        
        for tool_name, tool_func in self.tools.items():
            # Skip alive check if not enabled
            if tool_name == 'alive_check' and not self.check_alive:
                self.log("Skipping alive check (not enabled)")
                continue
            
            self.log(f"Running {tool_name}...")
            tool_func()
        
        self.log("Assessment complete")
    
    def run_all(self):
        """Run all enabled tools"""
        self.log(f"Starting security assessment for {self.domain}")
        self.log(f"Output directory: {self.output_dir}")
        
        for tool_name, tool_func in self.tools.items():
            try:
                tool_func()
            except Exception as e:
                self.log(f"Unexpected error running {tool_name}: {e}")
                self.results[tool_name] = {'status': 'error', 'error': str(e)}
        
        report_file = self.generate_report()
        self.log(f"Security assessment completed. Report: {report_file}")
        
        return report_file

def main():
    parser = argparse.ArgumentParser(
        description="Security Automation Orchestrator - Run all security tools and generate reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orchestrator.py example.com
  python orchestrator.py example.com --all
  python orchestrator.py example.com --tools directory_traversal,insecure_configuration
  python orchestrator.py example.com --output /path/to/output
        """
    )
    
    domain = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    scope_file = sys.argv[3] if len(sys.argv) > 3 else None
    rate_limit = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    check_alive = sys.argv[5].lower() == 'true' if len(sys.argv) > 5 else False
    
    orchestrator = SecurityOrchestrator(domain, output_dir, scope_file, rate_limit, check_alive)
    orchestrator.run_all()
    report_file = orchestrator.generate_report()
    print(f"Report generated in {orchestrator.output_dir}")
    
    print(f"\n{'='*60}")
    print(f"Assessment completed successfully!")
    print(f"Report: {report_file}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
