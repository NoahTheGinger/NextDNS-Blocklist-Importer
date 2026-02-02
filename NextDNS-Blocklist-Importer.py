#!/usr/bin/env python3
"""
NextDNS Blocklist Importer for Pythonista (iOS)

This script parses various blocklist formats and adds the domains
to a NextDNS profile using their API.

Supported formats:
- Hosts files (0.0.0.0/127.0.0.1 domain.com)
- AdGuard/uBlock Origin syntax (||domain.com^)
- Adblock Plus syntax
- Domain-only lists
- DNSMasq format
- Pi-hole format

Uses efficient batch PUT to update the entire denylist in a single API call.

Author: Claude
"""

import re
import sys
import json
from typing import Set, List, Optional, Callable
from urllib.parse import urlparse
from dataclasses import dataclass, field
from enum import Enum, auto

# Standard library imports that work everywhere
import os

# Try to import requests, fall back to urllib if not available
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

# Pythonista-specific imports
try:
    import dialogs
    import console
    import ui
    PYTHONISTA = True
except ImportError:
    PYTHONISTA = False
    print("Note: Running outside Pythonista. UI features disabled.")


class BlocklistFormat(Enum):
    """Supported blocklist formats."""
    HOSTS = auto()
    ADGUARD = auto()
    ADBLOCK_PLUS = auto()
    DOMAIN_ONLY = auto()
    DNSMASQ = auto()
    PIHOLE = auto()
    UNKNOWN = auto()


@dataclass
class ParserResult:
    """Result of parsing a blocklist."""
    domains: Set[str] = field(default_factory=set)
    whitelisted: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)
    format_detected: BlocklistFormat = BlocklistFormat.UNKNOWN
    total_lines: int = 0
    valid_lines: int = 0


class BlocklistParser:
    """
    Parser for various blocklist formats.
    Automatically detects format and extracts domains.
    """
    
    # Regex patterns for different formats
    PATTERNS = {
        # Hosts file: 0.0.0.0 or 127.0.0.1 followed by domain
        'hosts': re.compile(
            r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\s*$'
        ),
        # AdGuard/uBlock: ||domain.com^ or ||domain.com
        'adguard_block': re.compile(
            r'^\|\|([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\^?\s*$'
        ),
        # AdGuard whitelist: @@||domain.com^
        'adguard_whitelist': re.compile(
            r'^@@\|\|([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\^?\s*$'
        ),
        # DNSMasq: address=/domain.com/
        'dnsmasq': re.compile(
            r'^address=/([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})/(?:0\.0\.0\.0|127\.0\.0\.1|)?\s*$'
        ),
        # Pi-hole format (similar to hosts but may have additional syntax)
        'pihole': re.compile(
            r'^(?:0\.0\.0\.0|127\.0\.0\.1|\d+\.\d+\.\d+\.\d+)\s+([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})(?:\s+#.*)?$'
        ),
        # Domain only (just a domain per line)
        'domain_only': re.compile(
            r'^([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})\s*$'
        ),
        # Adblock Plus element hiding (to skip)
        'abp_element': re.compile(r'.*##.*|.*#@#.*'),
        # Adblock Plus URL filter with options (extract domain if possible)
        'abp_with_options': re.compile(
            r'^\|\|([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\^?\$[a-zA-Z0-9,=-]+$'
        ),
    }
    
    # Domains to always skip (localhost, local addresses, etc.)
    SKIP_DOMAINS = {
        'localhost', 'localhost.localdomain', 'local',
        'broadcasthost', 'ip6-localhost', 'ip6-loopback',
        'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes',
        'ip6-allrouters', 'ip6-allhosts', '0.0.0.0',
    }
    
    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        """Check if a domain is valid and should be included."""
        if not domain:
            return False
        
        domain = domain.lower().strip()
        
        # Skip known invalid domains
        if domain in cls.SKIP_DOMAINS:
            return False
        
        # Skip IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # Skip domains that are too short or invalid
        if len(domain) < 4 or '.' not in domain:
            return False
        
        # Skip domains with invalid characters
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$', domain):
            return False
        
        return True
    
    @classmethod
    def detect_format(cls, lines: List[str]) -> BlocklistFormat:
        """Detect the format of a blocklist from sample lines."""
        # Count matches for each format
        format_counts = {fmt: 0 for fmt in BlocklistFormat}
        
        sample_lines = [l.strip() for l in lines[:100] if l.strip() and not l.strip().startswith('#')]
        
        for line in sample_lines:
            if cls.PATTERNS['hosts'].match(line) or cls.PATTERNS['pihole'].match(line):
                format_counts[BlocklistFormat.HOSTS] += 1
            elif cls.PATTERNS['adguard_block'].match(line) or cls.PATTERNS['adguard_whitelist'].match(line):
                format_counts[BlocklistFormat.ADGUARD] += 1
            elif cls.PATTERNS['dnsmasq'].match(line):
                format_counts[BlocklistFormat.DNSMASQ] += 1
            elif cls.PATTERNS['abp_with_options'].match(line):
                format_counts[BlocklistFormat.ADBLOCK_PLUS] += 1
            elif cls.PATTERNS['domain_only'].match(line):
                format_counts[BlocklistFormat.DOMAIN_ONLY] += 1
        
        # Return the format with the most matches
        best_format = max(format_counts, key=format_counts.get)
        if format_counts[best_format] > 0:
            return best_format
        return BlocklistFormat.UNKNOWN
    
    @classmethod
    def parse_line(cls, line: str) -> tuple[Optional[str], bool]:
        """
        Parse a single line and return (domain, is_whitelist).
        Returns (None, False) if the line should be skipped.
        """
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#') or line.startswith('!'):
            return None, False
        
        # Skip ABP element hiding rules
        if cls.PATTERNS['abp_element'].match(line):
            return None, False
        
        # Check for AdGuard whitelist
        match = cls.PATTERNS['adguard_whitelist'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, True
            return None, False
        
        # Check for AdGuard block
        match = cls.PATTERNS['adguard_block'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, False
            return None, False
        
        # Check for ABP with options
        match = cls.PATTERNS['abp_with_options'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, False
            return None, False
        
        # Check for hosts file format
        match = cls.PATTERNS['hosts'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, False
            return None, False
        
        # Check for Pi-hole format
        match = cls.PATTERNS['pihole'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, False
            return None, False
        
        # Check for DNSMasq format
        match = cls.PATTERNS['dnsmasq'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, False
            return None, False
        
        # Check for domain-only format
        match = cls.PATTERNS['domain_only'].match(line)
        if match:
            domain = match.group(1).lower()
            if cls.is_valid_domain(domain):
                return domain, False
            return None, False
        
        return None, False
    
    @classmethod
    def parse(cls, content: str, progress_callback: Optional[Callable] = None) -> ParserResult:
        """Parse blocklist content and return extracted domains."""
        result = ParserResult()
        lines = content.splitlines()
        result.total_lines = len(lines)
        
        # Detect format
        result.format_detected = cls.detect_format(lines)
        
        for i, line in enumerate(lines):
            domain, is_whitelist = cls.parse_line(line)
            
            if domain:
                result.valid_lines += 1
                if is_whitelist:
                    result.whitelisted.add(domain)
                else:
                    result.domains.add(domain)
            
            # Report progress every 1000 lines
            if progress_callback and i % 1000 == 0:
                progress_callback(i, result.total_lines)
        
        # Remove whitelisted domains from blocked domains
        result.domains -= result.whitelisted
        
        return result


class NextDNSClient:
    """
    Client for NextDNS API.
    
    Uses efficient batch operations:
    - GET /denylist to fetch current list
    - PUT /denylist to replace entire list in one request
    """
    
    BASE_URL = "https://api.nextdns.io"
    
    def __init__(self, api_key: str, profile_id: str):
        self.api_key = api_key
        self.profile_id = profile_id
        self.headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def _request(self, method: str, endpoint: str, data: Optional[any] = None) -> dict:
        """Make an API request."""
        url = f"{self.BASE_URL}/profiles/{self.profile_id}{endpoint}"
        
        if HAS_REQUESTS:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data,
                timeout=120  # Longer timeout for large batch operations
            )
            response.raise_for_status()
            if response.text:
                return response.json()
            return {}
        else:
            # Fallback to urllib
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode() if data else None,
                headers=self.headers,
                method=method
            )
            with urllib.request.urlopen(req, timeout=120) as response:
                content = response.read().decode()
                if content:
                    return json.loads(content)
                return {}
    
    def get_denylist(self) -> List[dict]:
        """
        Get current denylist.
        Returns list of {"id": "domain.com", "active": true/false}
        """
        result = self._request("GET", "/denylist")
        return result.get("data", [])
    
    def get_allowlist(self) -> List[dict]:
        """
        Get current allowlist.
        Returns list of {"id": "domain.com", "active": true/false}
        """
        result = self._request("GET", "/allowlist")
        return result.get("data", [])
    
    def set_denylist(self, domains: List[dict]) -> dict:
        """
        Replace the entire denylist with a new list.
        
        This is the efficient batch operation - one API call for all domains!
        
        Args:
            domains: List of {"id": "domain.com", "active": true/false}
        
        Returns:
            API response
        """
        return self._request("PUT", "/denylist", domains)
    
    def add_to_denylist_single(self, domain: str, active: bool = True) -> dict:
        """Add a single domain to the denylist (less efficient, use set_denylist for batch)."""
        data = {"id": domain, "active": active}
        return self._request("POST", "/denylist", data)
    
    def add_domains_batch(
        self,
        new_domains: Set[str],
        merge_existing: bool = True,
        active: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Add multiple domains to the denylist efficiently using PUT.
        
        This fetches the current denylist, merges new domains, and replaces
        the entire list in a single API call.
        
        Args:
            new_domains: Set of domain strings to add
            merge_existing: If True, preserve existing denylist entries
            active: Whether new domains should be active (blocking)
            progress_callback: Optional callback for progress updates
        
        Returns:
            dict with 'added', 'existing', 'total' counts
        """
        results = {
            "added": 0,
            "existing": 0,
            "total": 0,
            "errors": []
        }
        
        if progress_callback:
            progress_callback("Fetching current denylist...", 0, 100)
        
        # Get existing denylist
        existing_list = []
        existing_domains = set()
        
        if merge_existing:
            try:
                existing_list = self.get_denylist()
                existing_domains = {entry["id"].lower() for entry in existing_list}
                if progress_callback:
                    progress_callback(f"Found {len(existing_list)} existing entries", 10, 100)
            except Exception as e:
                results["errors"].append(f"Failed to fetch existing denylist: {e}")
                # Continue anyway - we'll just add new domains
        
        # Build combined list
        if progress_callback:
            progress_callback("Building combined list...", 20, 100)
        
        combined_list = list(existing_list)  # Keep existing entries as-is
        
        # Add new domains that don't already exist
        for domain in new_domains:
            domain_lower = domain.lower()
            if domain_lower not in existing_domains:
                combined_list.append({"id": domain_lower, "active": active})
                results["added"] += 1
            else:
                results["existing"] += 1
        
        results["total"] = len(combined_list)
        
        if results["added"] == 0:
            if progress_callback:
                progress_callback("No new domains to add", 100, 100)
            return results
        
        # Send the combined list with PUT (single API call!)
        if progress_callback:
            progress_callback(f"Uploading {len(combined_list)} domains...", 50, 100)
        
        try:
            self.set_denylist(combined_list)
            if progress_callback:
                progress_callback("Upload complete!", 100, 100)
        except Exception as e:
            results["errors"].append(f"Failed to update denylist: {e}")
            raise
        
        return results
    
    def get_profile_info(self) -> dict:
        """Get profile information to verify credentials."""
        return self._request("GET", "")


def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    if HAS_REQUESTS:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        return response.text
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "NextDNS-Blocklist-Importer/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read().decode('utf-8', errors='ignore')


# ============================================================================
# Pythonista UI
# ============================================================================

if PYTHONISTA:
    class BlocklistImporterUI:
        """Pythonista UI for the blocklist importer."""
        
        def __init__(self):
            self.api_key = "NEXTDNS_API_KEY"
            self.profile_id = "NEXTDNS_PROFILE_ID"
            self.urls = []
            self.local_file_content = None
            self.local_file_name = None
        
        def show_config_dialog(self) -> bool:
            """Show configuration dialog for API key and profile ID."""
            fields = [
                {"title": "NextDNS API Key", "type": "text", "key": "api_key", "value": self.api_key},
                {"title": "Profile ID", "type": "text", "key": "profile_id", "value": self.profile_id},
            ]
            
            result = dialogs.form_dialog(title="NextDNS Configuration", fields=fields)
            
            if result:
                self.api_key = result.get("api_key", "").strip()
                self.profile_id = result.get("profile_id", "").strip()
                return bool(self.api_key and self.profile_id)
            return False
        
        def show_url_input(self) -> bool:
            """Show dialog for entering blocklist URLs."""
            result = dialogs.text_dialog(
                title="Blocklist URLs",
                text="Enter blocklist URLs (one per line):\n\n" + "\n".join(self.urls)
            )
            
            if result:
                self.urls = [url.strip() for url in result.strip().split("\n") if url.strip()]
                return bool(self.urls)
            return False
        
        def pick_local_file(self) -> bool:
            """Let user pick a local file."""
            try:
                # Use pick_document for file picking
                picked = dialogs.pick_document(types=["public.text", "public.plain-text"])
                if picked:
                    with open(picked, 'r', encoding='utf-8', errors='ignore') as f:
                        self.local_file_content = f.read()
                    self.local_file_name = os.path.basename(picked)
                    return True
            except Exception as e:
                console.alert("Error", f"Failed to read file: {e}")
            return False
        
        def show_source_selection(self) -> Optional[str]:
            """Show dialog to select blocklist source."""
            try:
                choice = dialogs.alert(
                    "Select Source",
                    "Choose blocklist source:",
                    "Remote URLs",
                    "Local File",
                    "Both"
                )
                
                if choice == 1:
                    return "urls"
                elif choice == 2:
                    return "local"
                elif choice == 3:
                    return "both"
            except KeyboardInterrupt:
                pass
            return None
        
        def show_merge_option(self) -> bool:
            """Ask user whether to merge with existing list or replace."""
            try:
                choice = dialogs.alert(
                    "Merge Options",
                    "How should new domains be added?",
                    "Merge (keep existing)",
                    "Replace (clear existing)"
                )
                return choice == 1  # True = merge, False = replace
            except KeyboardInterrupt:
                return True  # Default to merge for safety
        
        def run(self):
            """Run the importer UI."""
            console.clear()
            console.set_font("Menlo", 14)
            print("=" * 50)
            print("NextDNS Blocklist Importer")
            print("(Efficient Batch Mode)")
            print("=" * 50)
            print()
            
            # Get API configuration
            if not self.show_config_dialog():
                print("Configuration cancelled.")
                return
            
            # Verify API credentials
            print("Verifying API credentials...")
            try:
                client = NextDNSClient(self.api_key, self.profile_id)
                profile_info = client.get_profile_info()
                print(f"✓ Connected to profile: {profile_info.get('name', self.profile_id)}")
            except Exception as e:
                console.alert("Error", f"Failed to connect to NextDNS: {e}")
                return
            
            # Select source
            source = self.show_source_selection()
            if not source:
                print("Source selection cancelled.")
                return
            
            all_domains = set()
            
            # Handle URL sources
            if source in ("urls", "both"):
                if self.show_url_input():
                    for url in self.urls:
                        print(f"\nFetching: {url}")
                        try:
                            content = fetch_url(url)
                            result = BlocklistParser.parse(content)
                            print(f"  Format: {result.format_detected.name}")
                            print(f"  Domains found: {len(result.domains)}")
                            all_domains.update(result.domains)
                        except Exception as e:
                            print(f"  Error: {e}")
            
            # Handle local file
            if source in ("local", "both"):
                if self.pick_local_file():
                    print(f"\nParsing local file: {self.local_file_name}")
                    result = BlocklistParser.parse(self.local_file_content)
                    print(f"  Format: {result.format_detected.name}")
                    print(f"  Domains found: {len(result.domains)}")
                    all_domains.update(result.domains)
            
            if not all_domains:
                console.alert("No Domains", "No valid domains were found in the blocklists.")
                return
            
            print(f"\nTotal unique domains to add: {len(all_domains)}")
            
            # Ask about merge options
            merge_existing = self.show_merge_option()
            
            # Confirm before adding
            try:
                action = "merge with" if merge_existing else "replace"
                confirm = dialogs.alert(
                    "Confirm Import",
                    f"Add {len(all_domains)} domains ({action} existing)?",
                    "Yes, Continue",
                    "Cancel"
                )
                
                if confirm != 1:
                    print("Import cancelled.")
                    return
            except KeyboardInterrupt:
                print("Import cancelled.")
                return
            
            # Add domains using efficient batch operation
            print("\nUpdating NextDNS denylist...")
            print("(Using efficient single-request batch mode)")
            
            def progress_callback(message, current, total):
                if isinstance(message, str):
                    print(f"  {message}")
                else:
                    pct = (current / total) * 100
                    print(f"\r  Progress: {pct:.1f}%", end="")
            
            try:
                results = client.add_domains_batch(
                    all_domains,
                    merge_existing=merge_existing,
                    progress_callback=progress_callback
                )
                print()
                print(f"\n✓ New domains added: {results['added']}")
                print(f"○ Already existed: {results['existing']}")
                print(f"● Total in denylist: {results['total']}")
                
                if results['errors']:
                    print("\nWarnings:")
                    for error in results['errors']:
                        print(f"  - {error}")
                
                console.alert("Complete", 
                    f"Successfully updated NextDNS denylist!\n\n"
                    f"Added: {results['added']} new domains\n"
                    f"Total: {results['total']} domains"
                )
            except Exception as e:
                console.alert("Error", f"Failed to update denylist: {e}")


# ============================================================================
# Command Line Interface (for non-Pythonista use)
# ============================================================================

def cli_main():
    """Command line interface for non-Pythonista environments."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Parse blocklists and add domains to NextDNS (efficient batch mode)"
    )
    parser.add_argument(
        "--api-key", "-k",
        required=True,
        help="NextDNS API key"
    )
    parser.add_argument(
        "--profile", "-p",
        required=True,
        help="NextDNS profile ID"
    )
    parser.add_argument(
        "--urls", "-u",
        nargs="*",
        default=[],
        help="URLs of blocklists to fetch"
    )
    parser.add_argument(
        "--files", "-f",
        nargs="*",
        default=[],
        help="Local files to parse"
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Parse and show domains without adding to NextDNS"
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace existing denylist instead of merging"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output parsed domains to a file"
    )
    
    args = parser.parse_args()
    
    if not args.urls and not args.files:
        parser.error("At least one --urls or --files must be specified")
    
    all_domains = set()
    
    # Process URLs
    for url in args.urls:
        print(f"Fetching: {url}")
        try:
            content = fetch_url(url)
            result = BlocklistParser.parse(content)
            print(f"  Format: {result.format_detected.name}")
            print(f"  Domains: {len(result.domains)}")
            all_domains.update(result.domains)
        except Exception as e:
            print(f"  Error: {e}")
    
    # Process local files
    for filepath in args.files:
        print(f"Reading: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            result = BlocklistParser.parse(content)
            print(f"  Format: {result.format_detected.name}")
            print(f"  Domains: {len(result.domains)}")
            all_domains.update(result.domains)
        except Exception as e:
            print(f"  Error: {e}")
    
    print(f"\nTotal unique domains: {len(all_domains)}")
    
    # Output to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            for domain in sorted(all_domains):
                f.write(domain + "\n")
        print(f"Domains written to: {args.output}")
    
    # Add to NextDNS unless dry-run
    if not args.dry_run:
        print("\nConnecting to NextDNS...")
        client = NextDNSClient(args.api_key, args.profile)
        
        try:
            profile = client.get_profile_info()
            print(f"Profile: {profile.get('name', args.profile)}")
        except Exception as e:
            print(f"Error connecting: {e}")
            return 1
        
        print("\nUpdating denylist (efficient batch mode)...")
        
        def progress(message, current, total):
            print(f"  {message}")
        
        try:
            results = client.add_domains_batch(
                all_domains,
                merge_existing=not args.replace,
                progress_callback=progress
            )
            
            print(f"\n✓ New domains added: {results['added']}")
            print(f"○ Already existed: {results['existing']}")
            print(f"● Total in denylist: {results['total']}")
            
            if results['errors']:
                print("\nWarnings:")
                for error in results['errors']:
                    print(f"  - {error}")
        except Exception as e:
            print(f"\nError: {e}")
            return 1
    
    return 0


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point."""
    if PYTHONISTA:
        ui_app = BlocklistImporterUI()
        ui_app.run()
    else:
        sys.exit(cli_main())


if __name__ == "__main__":
    main()
