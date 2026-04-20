"""
Severity Scorer for Vulnerability Assessment
Assigns CVSS-like severity scores to different vulnerability types
"""


class SeverityScorer:
    """Calculate severity scores for vulnerabilities based on type and context"""
    
    # Base scores for different vulnerability types (0-10 scale)
    BASE_SCORES = {
        'directory_traversal': 7.5,  # High severity
        'insecure_configuration': 8.0,  # High severity (exposed keys)
        'subdomain_takeover': 9.0,  # Critical severity
        'rce': 10.0,  # Critical severity
        'sqli': 10.0,  # Critical severity
    }
    
    # Severity levels
    SEVERITY_LEVELS = {
        (0.0, 3.9): 'Low',
        (4.0, 6.9): 'Medium',
        (7.0, 8.9): 'High',
        (9.0, 10.0): 'Critical',
    }
    
    def get_severity_level(self, score):
        """Convert numeric score to severity level"""
        for (min_score, max_score), level in self.SEVERITY_LEVELS.items():
            if min_score <= score <= max_score:
                return level
        return 'Unknown'
    
    def score_directory_traversal(self, vuln):
        """Score directory traversal vulnerability"""
        base_score = self.BASE_SCORES['directory_traversal']
        
        # Adjustments based on context
        url = vuln.get('url', '')
        status_code = vuln.get('status_code', '')
        
        # Higher score if it actually returned content (not error)
        if status_code and status_code != 'ERROR':
            base_score += 0.5
        
        # Higher score for sensitive paths
        if any(path in url.lower() for path in ['/etc/passwd', '/etc/shadow', '/proc/', '/windows/']):
            base_score += 1.0
        
        return min(10.0, base_score)
    
    def score_insecure_configuration(self, vuln):
        """Score insecure configuration (exposed keys)"""
        base_score = self.BASE_SCORES['insecure_configuration']
        
        key_type = vuln.get('key_type', '')
        key_value = vuln.get('key_value', '')
        
        # Critical keys get higher scores
        critical_keys = [
            'AWS Secret Key', 'Stripe Secret Key', 'GitHub Personal Access Token',
            'GitLab Personal Access Token', 'Slack Bot Token', 'Slack User Token',
            'OpenAI API Key', 'Anthropic API Key', 'Firebase Database Secret'
        ]
        
        if any(critical in key_type for critical in critical_keys):
            base_score += 1.5
        elif 'Test' in key_type or 'test' in key_value.lower():
            base_score -= 2.0  # Lower score for test keys
        
        return min(10.0, max(0.0, base_score))
    
    def score_subdomain_takeover(self, vuln):
        """Score subdomain takeover vulnerability"""
        base_score = self.BASE_SCORES['subdomain_takeover']
        
        # All subdomain takeovers are critical, but can adjust based on service
        status = vuln.get('status', '')
        
        # Slightly lower score if it's a known service that might not be critical
        if 'herokuapp.com' in status.lower() or 'github.io' in status.lower():
            base_score -= 0.5
        
        return min(10.0, max(0.0, base_score))
    
    def score_rce(self, vuln):
        """Score RCE vulnerability"""
        # RCE is always critical
        return self.BASE_SCORES['rce']
    
    def score_sqli(self, vuln):
        """Score SQL injection vulnerability"""
        # SQLi is always critical
        return self.BASE_SCORES['sqli']
    
    def score_vulnerability(self, vuln_type, vuln):
        """Score a vulnerability based on its type"""
        scorers = {
            'directory_traversal': self.score_directory_traversal,
            'insecure_configuration': self.score_insecure_configuration,
            'subdomain_takeover': self.score_subdomain_takeover,
            'rce': self.score_rce,
            'sqli': self.score_sqli,
        }
        
        scorer = scorers.get(vuln_type)
        if scorer:
            score = scorer(vuln)
            return {
                'score': round(score, 1),
                'severity': self.get_severity_level(score)
            }
        
        return {'score': 0.0, 'severity': 'Unknown'}
    
    def score_vulnerabilities(self, vulnerabilities):
        """Score all vulnerabilities"""
        scored_vulns = {}
        
        for vuln_type, vulns in vulnerabilities.items():
            scored_vulns[vuln_type] = []
            for vuln in vulns:
                scored = self.score_vulnerability(vuln_type, vuln)
                vuln_copy = vuln.copy()
                vuln_copy.update(scored)
                scored_vulns[vuln_type].append(vuln_copy)
        
        return scored_vulns
    
    def get_summary(self, scored_vulnerabilities):
        """Get summary statistics of scored vulnerabilities"""
        summary = {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }
        
        for vuln_type, vulns in scored_vulnerabilities.items():
            summary['by_type'][vuln_type] = {
                'total': len(vulns),
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            for vuln in vulns:
                severity = vuln.get('severity', 'Unknown')
                summary['total'] += 1
                summary['by_type'][vuln_type][severity.lower()] += 1
                
                if severity == 'Critical':
                    summary['critical'] += 1
                elif severity == 'High':
                    summary['high'] += 1
                elif severity == 'Medium':
                    summary['medium'] += 1
                elif severity == 'Low':
                    summary['low'] += 1
        
        return summary


if __name__ == "__main__":
    # Test the scorer
    scorer = SeverityScorer()
    
    # Test cases
    test_vulns = {
        'directory_traversal': [
            {'url': 'https://example.com/../../etc/passwd', 'status_code': '200'}
        ],
        'insecure_configuration': [
            {'key_type': 'AWS Secret Key', 'key_value': 'test123'}
        ]
    }
    
    scored = scorer.score_vulnerabilities(test_vulns)
    summary = scorer.get_summary(scored)
    
    print("Scored vulnerabilities:")
    for vuln_type, vulns in scored.items():
        print(f"\n{vuln_type}:")
        for vuln in vulns:
            print(f"  Score: {vuln['score']}, Severity: {vuln['severity']}")
    
    print("\nSummary:")
    print(summary)
