#!/usr/bin/env python3
"""
Commit Metadata Scanner
Scans git commit history for behavioral metadata exposure.
Uses TV/TVC ephemeral authentication for API access.
"""

import os
import re
import json
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class CommitFinding:
    repo: str
    commit_hash: str
    author_name: str
    author_email: str
    timestamp: datetime
    message: str
    severity: str
    invariant_id: str
    description: str
    remediation: str

class CommitMetadataScanner:
    def __init__(self, config_path: str = "config/ecosystems.yaml"):
        self.config = self._load_config(config_path)
        self.findings: List[CommitFinding] = []

    def _load_config(self, path: str) -> Dict:
        import yaml
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    def scan_repo(self, repo_path: str, repo_name: str) -> List[CommitFinding]:
        """Scan a single repository's commit history."""
        findings = []

        # Get full commit log
        log_cmd = [
            'git', '-C', repo_path, 'log',
            '--all', '--format=%H|%an|%ae|%ad|%s',
            '--date=iso-strict'
        ]

        try:
            result = subprocess.run(log_cmd, capture_output=True, text=True, check=True)
            commits = result.stdout.strip().split('\n')
        except subprocess.CalledProcessError:
            return findings

        for commit_line in commits:
            if not commit_line:
                continue

            parts = commit_line.split('|', 4)
            if len(parts) < 5:
                continue

            commit_hash, author_name, author_email, timestamp_str, message = parts

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError:
                continue

            # Check invariants
            finding = self._check_commit_invariants(
                repo_name, commit_hash, author_name, 
                author_email, timestamp, message
            )

            if finding:
                findings.append(finding)

        return findings

    def _check_commit_invariants(self, repo: str, commit_hash: str, 
                                  author_name: str, author_email: str,
                                  timestamp: datetime, message: str) -> Optional[CommitFinding]:
        """Check a single commit against GCAT/BCAT invariants."""

        # INV-006: Service identity required
        allowed_domains = [
            '@stegverse.org',
            '@gcat-bcat.engine',
            '@aact-e.org',
            '@stegghost.io'
        ]

        if not any(domain in author_email.lower() for domain in allowed_domains):
            # Check if it's a known service account
            service_names = ['StegVerse Bot', 'GCAT-BCAT Builder', 'TVC Agent']
            if author_name not in service_names:
                return CommitFinding(
                    repo=repo,
                    commit_hash=commit_hash,
                    author_name=author_name,
                    author_email=author_email,
                    timestamp=timestamp,
                    message=message,
                    severity='HIGH',
                    invariant_id='INV-006',
                    description=f'Commit from non-service identity: {author_email}',
                    remediation='commit_rewriter'
                )

        # INV-004: Behavioral pattern detection
        # Check for temporal anomalies (commits between 02:00-06:00)
        if 2 <= timestamp.hour <= 6:
            # Single late-night commit is not anomaly; pattern is
            # This is a simplified check; full implementation tracks patterns across history
            pass

        # Check message content against medical/family keywords
        message_lower = message.lower()

        # Load patterns from config
        patterns = self._load_patterns()

        for keyword in patterns.get('medical_keywords', []):
            if keyword.lower() in message_lower:
                return CommitFinding(
                    repo=repo,
                    commit_hash=commit_hash,
                    author_name=author_name,
                    author_email=author_email,
                    timestamp=timestamp,
                    message=message,
                    severity='CRITICAL',
                    invariant_id='INV-001',
                    description=f'Medical keyword in commit message: {keyword}',
                    remediation='immediate_removal'
                )

        for keyword in patterns.get('family_keywords', []):
            if keyword.lower() in message_lower:
                return CommitFinding(
                    repo=repo,
                    commit_hash=commit_hash,
                    author_name=author_name,
                    author_email=author_email,
                    timestamp=timestamp,
                    message=message,
                    severity='CRITICAL',
                    invariant_id='INV-002',
                    description=f'Family keyword in commit message: {keyword}',
                    remediation='immediate_removal'
                )

        return None

    def _load_patterns(self) -> Dict:
        import yaml
        with open('config/patterns.yaml', 'r') as f:
            return yaml.safe_load(f)

    def analyze_temporal_patterns(self, commits: List[Dict]) -> List[Dict]:
        """Analyze commit timestamps for behavioral patterns."""
        if not commits:
            return []

        anomalies = []
        timestamps = [c['timestamp'] for c in commits]
        timestamps.sort()

        # Check for regular 02:00-06:00 commits
        late_night_commits = [t for t in timestamps if 2 <= t.hour <= 6]
        total_commits = len(timestamps)

        if total_commits > 0 and len(late_night_commits) / total_commits > 0.3:
            anomalies.append({
                'type': 'temporal_anomaly',
                'severity': 'HIGH',
                'invariant_id': 'INV-004',
                'description': f'{len(late_night_commits)/total_commits:.1%} of commits between 02:00-06:00',
                'remediation': 'timestamp_obfuscation'
            })

        # Check for gaps > 72h followed by bursts
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i-1]
            if gap > timedelta(hours=72):
                # Check if followed by burst
                burst_end = min(i + 20, len(timestamps))
                burst_count = burst_end - i
                if burst_count > 10:
                    anomalies.append({
                        'type': 'gap_then_burst',
                        'severity': 'HIGH',
                        'invariant_id': 'INV-004',
                        'description': f'Gap of {gap.days} days followed by {burst_count} commits',
                        'remediation': 'timestamp_obfuscation'
                    })

        return anomalies

    def generate_report(self) -> Dict[str, Any]:
        """Generate scan report with findings."""
        return {
            'scan_type': 'commit_metadata',
            'timestamp': datetime.utcnow().isoformat(),
            'total_findings': len(self.findings),
            'findings_by_severity': self._group_by_severity(),
            'findings_by_invariant': self._group_by_invariant(),
            'findings': [self._finding_to_dict(f) for f in self.findings]
        }

    def _group_by_severity(self) -> Dict[str, int]:
        result = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in self.findings:
            result[f.severity] = result.get(f.severity, 0) + 1
        return result

    def _group_by_invariant(self) -> Dict[str, int]:
        result = {}
        for f in self.findings:
            result[f.invariant_id] = result.get(f.invariant_id, 0) + 1
        return result

    def _finding_to_dict(self, finding: CommitFinding) -> Dict:
        return {
            'repo': finding.repo,
            'commit_hash': finding.commit_hash,
            'author_name': finding.author_name,
            'author_email': finding.author_email,
            'timestamp': finding.timestamp.isoformat(),
            'message': finding.message,
            'severity': finding.severity,
            'invariant_id': finding.invariant_id,
            'description': finding.description,
            'remediation': finding.remediation
        }

if __name__ == '__main__':
    scanner = CommitMetadataScanner()
    # Example usage would scan repos from ecosystems.yaml
    print("Commit Metadata Scanner initialized")
    print("Use scan_repo(repo_path, repo_name) to scan individual repositories")
