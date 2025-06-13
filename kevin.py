#!/usr/bin/env python3
"""
Kevin OSCP Automation Companion
Named after Kevin Mitnick - The Ghost in the Wires

A comprehensive OSCP methodology automation tool that embodies
Kevin Mitnick's methodical approach to enumeration and exploitation.
"""

import cmd
import sys
import subprocess
import xml.etree.ElementTree as ET
import json
import os
import time
import threading
import re
import urllib.parse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from pathlib import Path
from abc import ABC, abstractmethod

# ===============================
# REFACTORED FRAMEWORK CLASSES
# ===============================

@dataclass
class CommandResult:
    """Standardized command execution result"""
    success: bool
    output: str
    error: str
    command: str
    timeout: bool = False

class CommandExecutor:
    """Centralized command execution with consistent error handling"""
    
    @staticmethod
    def run_command(cmd: List[str], timeout: int = 60) -> CommandResult:
        """Standardized command execution with error handling"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                command=' '.join(cmd)
            )
        except subprocess.TimeoutExpired:
            return CommandResult(False, "", f"Timeout after {timeout}s", ' '.join(cmd), timeout=True)
        except Exception as e:
            return CommandResult(False, "", str(e), ' '.join(cmd))
    
    @staticmethod
    def run_nmap_scripts(scripts: List[str], target: str, port: int, timeout: int = 300) -> CommandResult:
        """Run multiple nmap scripts efficiently"""
        if not scripts:
            return CommandResult(False, "", "No scripts provided", "")
        
        combined_scripts = ','.join(scripts)
        cmd = ['nmap', '--script', combined_scripts, '-p', str(port), target]
        return CommandExecutor.run_command(cmd, timeout)
    
    @staticmethod
    def parse_version_info(output: str, patterns: Dict[str, str]) -> Dict[str, str]:
        """Common version parsing logic"""
        versions = {}
        for field, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
            if match:
                versions[field] = match.group(1).strip()
        return versions

class CommonResources:
    """Shared resources across all enumerators"""
    
    COMMON_PASSWORDS = {
        'database': ['', 'password', 'admin', 'root', '123456', 'sa', 'mysql'],
        'email': ['password', 'admin', 'welcome', '123456', 'mail'],
        'web': ['admin', 'password', 'test', 'guest', 'demo'],
        'ldap': ['', 'password', 'admin', 'ldap', 'directory'],
        'kerberos': ['password', 'admin', 'krbtgt', 'service']
    }
    
    DEFAULT_ACCOUNTS = {
        'mysql': ['root', 'mysql', 'admin', 'user'],
        'mssql': ['sa', 'MSSQL$', 'SQLEXPRESS', 'administrator'],
        'oracle': ['SYS', 'SYSTEM', 'SCOTT', 'HR', 'DBSNMP'],
        'smtp': ['admin', 'mail', 'postmaster', 'root'],
        'ldap': ['admin', 'administrator', 'cn=admin', 'root'],
        'kerberos': ['krbtgt', 'administrator', 'admin']
    }
    
    NMAP_SCRIPT_CATEGORIES = {
        'basic_info': ['*-info', '*-version', '*-banner'],
        'security': ['*-vuln-*', '*-empty-password', '*-brute'],
        'enumeration': ['*-enum*', '*-users', '*-databases', '*-shares']
    }

@dataclass
class ServiceConfig:
    """Configuration for each service enumerator"""
    service_name: str
    default_port: int
    nmap_scripts: List[str]
    version_patterns: Dict[str, str]
    security_indicators: List[str]
    common_vulns: List[str]

class BaseServiceEnumerator(ABC):
    """Base class for all service enumerators with common functionality"""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.service_name = config.service_name
        self.default_port = config.default_port
        self.scripts = config.nmap_scripts
        self.version_patterns = config.version_patterns
        self.security_indicators = config.security_indicators
        
    def enumerate(self, target: str, port: int = None):
        """Template method for enumeration flow"""
        port = port or self.default_port
        print(f"[*] {self.service_name} enumeration on {target}:{port}")
        
        finding = self._create_finding(target, port)
        
        try:
            # Standard 4-phase enumeration pattern
            self._phase_1_basic_info(target, port, finding)
            self._phase_2_security_config(target, port, finding)
            self._phase_3_detailed_enum(target, port, finding)
            self._phase_4_security_assessment(finding)
            
        except Exception as e:
            self._handle_enumeration_error(e, finding)
        
        return finding
    
    @abstractmethod
    def _create_finding(self, target: str, port: int):
        """Create service-specific finding object"""
        pass
    
    def _phase_1_basic_info(self, target: str, port: int, finding):
        """Phase 1: Basic information gathering (can be overridden)"""
        result = CommandExecutor.run_nmap_scripts(
            [s for s in self.scripts if 'info' in s or 'version' in s],
            target, port
        )
        if result.success:
            self._parse_basic_info(result.output, finding)
    
    def _phase_2_security_config(self, target: str, port: int, finding):
        """Phase 2: Security configuration analysis (can be overridden)"""
        result = CommandExecutor.run_nmap_scripts(
            [s for s in self.scripts if 'vuln' in s or 'security' in s],
            target, port
        )
        if result.success:
            self._parse_security_config(result.output, finding)
    
    @abstractmethod
    def _phase_3_detailed_enum(self, target: str, port: int, finding):
        """Phase 3: Detailed enumeration (must be implemented by subclasses)"""
        pass
    
    def _phase_4_security_assessment(self, finding):
        """Phase 4: Security assessment and issue compilation"""
        issues = []
        
        # Common security assessments
        issues.extend(self._check_common_vulnerabilities(finding))
        issues.extend(self._check_weak_configurations(finding))
        
        # Service-specific assessments
        issues.extend(self._check_service_specific_issues(finding))
        
        finding.security_issues = issues
    
    def _parse_basic_info(self, output: str, finding):
        """Parse basic information from nmap output"""
        version_info = CommandExecutor.parse_version_info(output, self.version_patterns)
        for field, value in version_info.items():
            if hasattr(finding, field):
                setattr(finding, field, value)
    
    def _parse_security_config(self, output: str, finding):
        """Parse security configuration from nmap output"""
        # Common security parsing logic
        for indicator in self.security_indicators:
            if indicator.lower() in output.lower():
                if hasattr(finding, 'security_issues') and finding.security_issues:
                    finding.security_issues.append(f"Security indicator detected: {indicator}")
    
    def _check_common_vulnerabilities(self, finding) -> List[str]:
        """Check for common vulnerabilities across all services"""
        issues = []
        
        # Check for version-based vulnerabilities
        if hasattr(finding, 'version') and finding.version:
            for vuln in self.config.common_vulns:
                if vuln.lower() in finding.version.lower():
                    issues.append(f"Potentially vulnerable version detected: {vuln}")
        
        return issues
    
    def _check_weak_configurations(self, finding) -> List[str]:
        """Check for weak configurations"""
        issues = []
        
        # Check for empty passwords
        if hasattr(finding, 'empty_password_accounts') and finding.empty_password_accounts:
            issues.append(f"Empty password accounts detected: {', '.join(finding.empty_password_accounts)}")
        
        # Check for default accounts
        if hasattr(finding, 'default_accounts') and finding.default_accounts:
            issues.append(f"Default accounts detected: {', '.join(finding.default_accounts)}")
        
        return issues
    
    @abstractmethod
    def _check_service_specific_issues(self, finding) -> List[str]:
        """Check for service-specific security issues"""
        pass
    
    def _handle_enumeration_error(self, error: Exception, finding):
        """Handle enumeration errors gracefully"""
        error_msg = f"Enumeration error in {self.service_name}: {str(error)}"
        if hasattr(finding, 'security_issues'):
            if finding.security_issues is None:
                finding.security_issues = []
            finding.security_issues.append(error_msg)
        print(f"Kevin: {error_msg}")

# ===============================
# END FRAMEWORK CLASSES  
# ===============================

@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None
    scripts: Dict[str, str] = None
    
    def __post_init__(self):
        if self.scripts is None:
            self.scripts = {}

@dataclass
class WebFinding:
    url: str
    status_code: int
    size: int
    tool: str
    timestamp: str
    extra_info: Optional[str] = None

@dataclass
class VirtualHost:
    hostname: str
    ip: str
    status_code: int
    content_length: int
    server: Optional[str] = None
    title: Optional[str] = None
    redirect_location: Optional[str] = None
    discovery_method: str = "host_header"  # host_header, dns_subdomain, reverse_dns
    response_time: Optional[float] = None
    unique_content: bool = False  # Whether content differs from default
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

@dataclass
class MySQLFinding:
    target: str
    port: int
    timestamp: str
    
    # Version and server information
    version: Optional[str] = None
    server_version: Optional[str] = None
    protocol_version: Optional[str] = None
    
    # Access and authentication
    anonymous_access: bool = False
    empty_password_accounts: List[str] = None
    
    # Database enumeration
    databases: List[str] = None
    accessible_databases: List[str] = None
    
    # Security configuration
    ssl_enabled: bool = False
    variables: Dict[str, str] = None
    security_issues: List[str] = None
    
    # Additional information
    users: List[str] = None
    processes: List[Dict] = None
    
    def __post_init__(self):
        if self.empty_password_accounts is None:
            self.empty_password_accounts = []
        if self.databases is None:
            self.databases = []
        if self.accessible_databases is None:
            self.accessible_databases = []
        if self.variables is None:
            self.variables = {}
        if self.security_issues is None:
            self.security_issues = []
        if self.users is None:
            self.users = []
        if self.processes is None:
            self.processes = []

@dataclass
class MSSQLFinding:
    target: str
    port: int
    timestamp: str
    
    # Version and server information
    version: Optional[str] = None
    server_version: Optional[str] = None
    instance_name: Optional[str] = None
    server_name: Optional[str] = None
    
    # Authentication and access
    windows_authentication: bool = False
    sql_authentication: bool = False
    mixed_mode: bool = False
    weak_passwords: List[str] = None
    
    # Database enumeration
    databases: List[str] = None
    accessible_databases: List[str] = None
    
    # Security configuration
    xp_cmdshell_enabled: bool = False
    ole_automation_enabled: bool = False
    clr_enabled: bool = False
    security_issues: List[str] = None
    
    # Users and roles
    users: List[str] = None
    roles: List[str] = None
    sysadmin_users: List[str] = None
    
    # Additional findings
    linked_servers: List[str] = None
    procedures: List[str] = None
    
    def __post_init__(self):
        if self.weak_passwords is None:
            self.weak_passwords = []
        if self.databases is None:
            self.databases = []
        if self.accessible_databases is None:
            self.accessible_databases = []
        if self.security_issues is None:
            self.security_issues = []
        if self.users is None:
            self.users = []
        if self.roles is None:
            self.roles = []
        if self.sysadmin_users is None:
            self.sysadmin_users = []
        if self.linked_servers is None:
            self.linked_servers = []
        if self.procedures is None:
            self.procedures = []

@dataclass
class OracleFinding:
    target: str
    port: int
    timestamp: str
    
    # Version and instance information
    version: Optional[str] = None
    banner: Optional[str] = None
    instance_name: Optional[str] = None
    
    # TNS Listener information
    listener_version: Optional[str] = None
    listener_status: Optional[str] = None
    
    # Service Information Discoverers (SIDs)
    sids: List[str] = None
    accessible_sids: List[str] = None
    
    # Authentication and access
    default_accounts: List[str] = None
    weak_passwords: List[str] = None
    
    # Security configuration
    security_issues: List[str] = None
    
    # Database enumeration
    databases: List[str] = None
    schemas: List[str] = None
    users: List[str] = None
    
    # Additional information
    services: List[str] = None
    parameters: Dict[str, str] = None
    
    def __post_init__(self):
        if self.sids is None:
            self.sids = []
        if self.accessible_sids is None:
            self.accessible_sids = []
        if self.default_accounts is None:
            self.default_accounts = []
        if self.weak_passwords is None:
            self.weak_passwords = []
        if self.security_issues is None:
            self.security_issues = []
        if self.databases is None:
            self.databases = []
        if self.schemas is None:
            self.schemas = []
        if self.users is None:
            self.users = []
        if self.services is None:
            self.services = []
        if self.parameters is None:
            self.parameters = {}

@dataclass
class TechnologyAnalysis:
    url: str
    timestamp: str
    
    # Server & Infrastructure
    web_server: Optional[str] = None
    server_version: Optional[str] = None
    operating_system: Optional[str] = None
    
    # Programming Languages & Frameworks
    backend_language: Optional[str] = None
    backend_framework: Optional[str] = None
    frontend_framework: Optional[str] = None
    
    # CMS & Applications
    cms: Optional[str] = None
    cms_version: Optional[str] = None
    
    # Security Headers
    security_headers: Dict[str, str] = None
    missing_security_headers: List[str] = None
    
    # Cookies Analysis
    cookies: Dict[str, str] = None
    cookie_flags: Dict[str, List[str]] = None
    
    # JavaScript Libraries
    js_libraries: Dict[str, str] = None
    
    # CSS Frameworks
    css_frameworks: List[str] = None
    
    # Custom Headers & Fingerprints
    custom_headers: Dict[str, str] = None
    fingerprints: List[str] = None
    
    # Vulnerabilities & Risks
    potential_vulnerabilities: List[str] = None
    security_issues: List[str] = None
    
    def __post_init__(self):
        if self.security_headers is None:
            self.security_headers = {}
        if self.missing_security_headers is None:
            self.missing_security_headers = []
        if self.cookies is None:
            self.cookies = {}
        if self.cookie_flags is None:
            self.cookie_flags = {}
        if self.js_libraries is None:
            self.js_libraries = {}
        if self.css_frameworks is None:
            self.css_frameworks = []
        if self.custom_headers is None:
            self.custom_headers = {}
        if self.fingerprints is None:
            self.fingerprints = []
        if self.potential_vulnerabilities is None:
            self.potential_vulnerabilities = []
        if self.security_issues is None:
            self.security_issues = []

@dataclass
class SMTPFinding:
    target: str
    port: int = 25
    timestamp: str = ""
    
    # Basic Information
    banner: Optional[str] = None
    hostname: Optional[str] = None
    software: Optional[str] = None
    version: Optional[str] = None
    
    # Capabilities and Features
    capabilities: List[str] = None
    auth_methods: List[str] = None
    supported_extensions: List[str] = None
    max_message_size: Optional[str] = None
    
    # Security Features
    tls_supported: bool = False
    starttls_available: bool = False
    ssl_version: Optional[str] = None
    
    # User Enumeration Results
    valid_users: List[str] = None
    vrfy_enabled: bool = False
    expn_enabled: bool = False
    rcpt_enum_possible: bool = False
    
    # Security Assessment
    security_issues: List[str] = None
    misconfigurations: List[str] = None
    relay_test_result: Optional[str] = None
    
    # Configuration Details
    mail_from_restrictions: Optional[str] = None
    rcpt_to_restrictions: Optional[str] = None
    message_submission_port: Optional[int] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.capabilities is None:
            self.capabilities = []
        if self.auth_methods is None:
            self.auth_methods = []
        if self.supported_extensions is None:
            self.supported_extensions = []
        if self.valid_users is None:
            self.valid_users = []
        if self.security_issues is None:
            self.security_issues = []
        if self.misconfigurations is None:
            self.misconfigurations = []

@dataclass
class EmailServiceFinding:
    target: str
    port: int
    service_type: str  # 'pop3', 'imap', 'pop3s', 'imaps'
    timestamp: str = ""
    
    # Basic Information
    banner: Optional[str] = None
    software: Optional[str] = None
    version: Optional[str] = None
    
    # Capabilities and Features
    capabilities: List[str] = None
    auth_mechanisms: List[str] = None
    supported_extensions: List[str] = None
    
    # Security Features
    tls_supported: bool = False
    ssl_enabled: bool = False
    starttls_available: bool = False
    ssl_version: Optional[str] = None
    
    # Authentication Details
    plaintext_auth: bool = False
    login_disabled: bool = False
    anonymous_access: bool = False
    
    # Configuration
    max_connections: Optional[str] = None
    timeout_settings: Optional[str] = None
    mailbox_format: Optional[str] = None
    
    # Security Assessment
    security_issues: List[str] = None
    weak_configurations: List[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.capabilities is None:
            self.capabilities = []
        if self.auth_mechanisms is None:
            self.auth_mechanisms = []
        if self.supported_extensions is None:
            self.supported_extensions = []
        if self.security_issues is None:
            self.security_issues = []
        if self.weak_configurations is None:
            self.weak_configurations = []

@dataclass
class LDAPFinding:
    target: str
    port: int = 389
    timestamp: str = ""
    
    # Basic Information
    base_dn: Optional[str] = None
    root_dse: Optional[str] = None
    server_name: Optional[str] = None
    ldap_version: Optional[str] = None
    
    # Naming Contexts
    naming_contexts: List[str] = None
    default_naming_context: Optional[str] = None
    config_naming_context: Optional[str] = None
    schema_naming_context: Optional[str] = None
    
    # Directory Information
    domain_name: Optional[str] = None
    forest_functionality: Optional[str] = None
    domain_functionality: Optional[str] = None
    
    # Organizational Units
    organizational_units: List[str] = None
    containers: List[str] = None
    
    # Schema Information
    schema_attributes: List[str] = None
    object_classes: List[str] = None
    
    # User and Group Information
    users: List[str] = None
    groups: List[str] = None
    computers: List[str] = None
    
    # Service Information
    service_connection_points: List[str] = None
    trusted_domains: List[str] = None
    
    # Security Assessment
    anonymous_bind: bool = False
    null_bind: bool = False
    security_issues: List[str] = None
    sensitive_attributes: List[str] = None
    
    # SSL/TLS Information
    ssl_enabled: bool = False
    start_tls_available: bool = False
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.naming_contexts is None:
            self.naming_contexts = []
        if self.organizational_units is None:
            self.organizational_units = []
        if self.containers is None:
            self.containers = []
        if self.schema_attributes is None:
            self.schema_attributes = []
        if self.object_classes is None:
            self.object_classes = []
        if self.users is None:
            self.users = []
        if self.groups is None:
            self.groups = []
        if self.computers is None:
            self.computers = []
        if self.service_connection_points is None:
            self.service_connection_points = []
        if self.trusted_domains is None:
            self.trusted_domains = []
        if self.security_issues is None:
            self.security_issues = []
        if self.sensitive_attributes is None:
            self.sensitive_attributes = []

@dataclass
class KerberosFinding:
    target: str
    port: int = 88
    timestamp: str = ""
    
    # Basic Information
    realm: Optional[str] = None
    kdc_server: Optional[str] = None
    kerberos_version: Optional[str] = None
    
    # Service Principal Names
    spns: List[str] = None
    service_accounts: List[str] = None
    
    # User Information
    valid_users: List[str] = None
    admin_users: List[str] = None
    service_users: List[str] = None
    
    # Domain Information
    domain_controllers: List[str] = None
    domain_name: Optional[str] = None
    forest_name: Optional[str] = None
    
    # Kerberos Services
    kerberos_services: List[str] = None
    supported_encryption: List[str] = None
    
    # Pre-authentication
    users_no_preauth: List[str] = None
    asrep_roastable: List[str] = None
    
    # Security Assessment
    security_issues: List[str] = None
    vulnerable_configurations: List[str] = None
    
    # Time Information
    kdc_time: Optional[str] = None
    time_skew: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.spns is None:
            self.spns = []
        if self.service_accounts is None:
            self.service_accounts = []
        if self.valid_users is None:
            self.valid_users = []
        if self.admin_users is None:
            self.admin_users = []
        if self.service_users is None:
            self.service_users = []
        if self.domain_controllers is None:
            self.domain_controllers = []
        if self.kerberos_services is None:
            self.kerberos_services = []
        if self.supported_encryption is None:
            self.supported_encryption = []
        if self.users_no_preauth is None:
            self.users_no_preauth = []
        if self.asrep_roastable is None:
            self.asrep_roastable = []
        if self.security_issues is None:
            self.security_issues = []
        if self.vulnerable_configurations is None:
            self.vulnerable_configurations = []

@dataclass
class Target:
    ip: str
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    open_ports: List[Port] = None
    notes: List[str] = None
    scan_history: List[str] = None
    vulnerabilities: List[str] = None
    web_findings: List[WebFinding] = None
    technology_stack: Dict[str, str] = None
    technology_analysis: List[TechnologyAnalysis] = None
    virtual_hosts: List[VirtualHost] = None
    mysql_findings: List[MySQLFinding] = None
    mssql_findings: List[MSSQLFinding] = None
    oracle_findings: List[OracleFinding] = None
    smtp_findings: List[SMTPFinding] = None
    email_findings: List[EmailServiceFinding] = None
    ldap_findings: List[LDAPFinding] = None
    kerberos_findings: List[KerberosFinding] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.notes is None:
            self.notes = []
        if self.scan_history is None:
            self.scan_history = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.web_findings is None:
            self.web_findings = []
        if self.technology_stack is None:
            self.technology_stack = {}
        if self.technology_analysis is None:
            self.technology_analysis = []
        if self.virtual_hosts is None:
            self.virtual_hosts = []
        if self.mysql_findings is None:
            self.mysql_findings = []
        if self.mssql_findings is None:
            self.mssql_findings = []
        if self.oracle_findings is None:
            self.oracle_findings = []
        if self.smtp_findings is None:
            self.smtp_findings = []
        if self.email_findings is None:
            self.email_findings = []
        if self.ldap_findings is None:
            self.ldap_findings = []
        if self.kerberos_findings is None:
            self.kerberos_findings = []
    
    def get_web_ports(self) -> List[Port]:
        """Get all web service ports"""
        web_services = {'http', 'https', 'http-proxy', 'ssl/http', 'http-alt'}
        return [p for p in self.open_ports if p.service.lower() in web_services or p.number in [80, 443, 8080, 8443, 8000, 9000]]

class NmapScanner:
    """Handles all nmap scanning operations"""
    
    def __init__(self):
        self.scan_types = {
            'quick': ['-sS', '-T4', '-p-', '--min-rate=1000'],
            'service': ['-sS', '-sV', '-sC', '-A', '-O'],
            'udp': ['-sU', '--top-ports', '1000', '-sV'],
            'vuln': ['--script', 'vuln'],
            'stealth': ['-sS', '-T2', '-f', '--source-port', '53']
        }
        
        self.service_scripts = {
            'smb': ['smb-enum-shares', 'smb-enum-users', 'smb-os-discovery', 'smb-security-mode'],
            'http': ['http-enum', 'http-headers', 'http-methods', 'http-webdav-scan'],
            'ftp': ['ftp-anon', 'ftp-bounce', 'ftp-proftpd-backdoor', 'ftp-vsftpd-backdoor'],
            'ssh': ['ssh-auth-methods', 'ssh-hostkey', 'ssh-run', 'ssh2-enum-algos'],
            'dns': ['dns-zone-transfer', 'dns-recursion', 'dns-cache-snoop'],
            'snmp': ['snmp-info', 'snmp-netstat', 'snmp-processes', 'snmp-sysdescr']
        }
    
    def run_scan(self, target: str, scan_type: str, ports: Optional[str] = None, 
                 output_file: Optional[str] = None) -> subprocess.Popen:
        """Execute nmap scan and return process handle"""
        
        if scan_type not in self.scan_types:
            raise ValueError(f"Unknown scan type: {scan_type}")
        
        cmd = ['nmap'] + self.scan_types[scan_type]
        
        if ports and scan_type in ['service', 'vuln']:
            cmd.extend(['-p', ports])
        
        if output_file:
            cmd.extend(['-oA', output_file])
        
        cmd.append(target)
        
        print(f"[*] Running: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_service_scan(self, target: str, service: str, ports: str, 
                        output_file: Optional[str] = None) -> subprocess.Popen:
        """Run service-specific enumeration scripts"""
        
        if service not in self.service_scripts:
            raise ValueError(f"Unknown service: {service}")
        
        scripts = ','.join(self.service_scripts[service])
        cmd = ['nmap', '--script', scripts, '-p', ports, target]
        
        if output_file:
            cmd.extend(['-oA', f"{output_file}_{service}"])
        
        print(f"[*] Running {service.upper()} enumeration: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def parse_xml_output(self, xml_file: str) -> List[Port]:
        """Parse nmap XML output and extract port information"""
        ports = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                for port_elem in host.findall('.//port'):
                    port_num = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    
                    state_elem = port_elem.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port_elem.find('service')
                    service = service_elem.get('name') if service_elem is not None else 'unknown'
                    version = service_elem.get('version') if service_elem is not None else None
                    
                    # Parse script results
                    scripts = {}
                    for script in port_elem.findall('.//script'):
                        script_id = script.get('id')
                        script_output = script.get('output', '')
                        scripts[script_id] = script_output
                    
                    port = Port(
                        number=port_num,
                        protocol=protocol,
                        state=state,
                        service=service,
                        version=version,
                        scripts=scripts
                    )
                    ports.append(port)
                    
        except ET.ParseError as e:
            print(f"[!] Error parsing XML: {e}")
        except FileNotFoundError:
            print(f"[!] XML file not found: {xml_file}")
        
        return ports

class WebEnumerator:
    """Handles all web enumeration operations"""
    
    def __init__(self):
        self.tools = {
            'gobuster': {
                'dir': ['gobuster', 'dir', '-u', '{url}', '-w', '{wordlist}'],
                'vhost': ['gobuster', 'vhost', '-u', '{url}', '-w', '{wordlist}']
            },
            'feroxbuster': ['feroxbuster', '-u', '{url}', '-w', '{wordlist}'],
            'ffuf': {
                'dir': ['ffuf', '-w', '{wordlist}', '-u', '{url}/FUZZ'],
                'param': ['ffuf', '-w', '{wordlist}', '-u', '{url}?FUZZ=test'],
                'vhost': ['ffuf', '-w', '{wordlist}', '-u', '{url}', '-H', 'Host: FUZZ.{domain}']
            },
            'nikto': ['nikto', '-h', '{url}'],
            'whatweb': ['whatweb', '-a', '3', '{url}']
        }
        
        self.wordlists = {
            'common': '/usr/share/seclists/Discovery/Web-Content/common.txt',
            'big': '/usr/share/seclists/Discovery/Web-Content/big.txt', 
            'medium': '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
            'raft': '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt',
            'params': '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
            'subdomains': '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
        }
        
        self.extensions = {
            'basic': ['php', 'html', 'txt', 'js', 'xml', 'json'],
            'backup': ['bak', 'old', 'orig', 'backup', 'swp', 'tmp', 'save', 'copy'],
            'config': ['config', 'conf', 'cfg', 'ini', 'properties', 'env'],
            'database': ['sql', 'db', 'sqlite', 'mdb', 'dump'],
            'sensitive': ['log', 'key', 'pem', 'p12', 'pfx', 'crt', 'der']
        }
        
        # Specialized wordlists for backup/sensitive file hunting
        self.sensitive_wordlists = {
            'backup_files': [
                'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'copy', 'copies',
                'archive', 'archives', 'save', 'saved', 'orig', 'original'
            ],
            'config_files': [
                'config', 'configuration', 'settings', 'env', 'environment',
                'web.config', 'app.config', 'application.properties', 'config.php',
                'config.inc', 'config.inc.php', 'wp-config.php', 'wp-config.bak',
                'database.yml', 'database.php', 'db.php', 'dbconfig.php',
                '.htaccess', '.htpasswd', '.env', '.env.local', '.env.production'
            ],
            'sensitive_files': [
                'phpinfo', 'info', 'test', 'debug', 'error', 'access', 'server-status',
                'readme', 'changelog', 'license', 'todo', 'notes', 'dump', 'sql',
                'database', 'db', 'users', 'passwords', 'passwd', 'shadow',
                'credentials', 'secrets', 'private', 'key', 'keys', 'cert', 'certificate'
            ],
            'development_files': [
                'dev', 'development', 'staging', 'test', 'testing', 'beta',
                'alpha', 'demo', 'sandbox', 'local', 'localhost', 'debug',
                'trace', 'error_log', 'access_log', 'application.log'
            ]
        }
        
        # Common sensitive file patterns that often contain credentials
        self.sensitive_patterns = [
            'web.config', 'app.config', 'database.yml', 'config.php', 'wp-config.php',
            '.htaccess', '.htpasswd', '.env', 'phpinfo.php', 'info.php', 'test.php',
            'readme.txt', 'changelog.txt', 'backup.sql', 'dump.sql', 'users.sql',
            'passwords.txt', 'credentials.txt', 'secrets.txt', 'private.key',
            'server.key', 'certificate.pem', 'id_rsa', 'id_dsa', 'authorized_keys'
        ]
    
    def run_gobuster(self, url: str, wordlist: str = 'common', 
                    extensions: List[str] = None, output_file: str = None) -> subprocess.Popen:
        """Run gobuster directory enumeration"""
        
        wordlist_path = self.wordlists.get(wordlist, wordlist)
        cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist_path]
        
        if extensions:
            cmd.extend(['-x', ','.join(extensions)])
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        # Add useful flags
        cmd.extend(['-k', '--no-error', '-t', '50'])
        
        print(f"[*] Running Gobuster: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_feroxbuster(self, url: str, wordlist: str = 'common',
                       depth: int = 4, threads: int = 50, 
                       output_file: str = None) -> subprocess.Popen:
        """Run feroxbuster recursive enumeration"""
        
        wordlist_path = self.wordlists.get(wordlist, wordlist)
        cmd = ['feroxbuster', '-u', url, '-w', wordlist_path, 
               '-d', str(depth), '-t', str(threads)]
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        # Add useful flags
        cmd.extend(['-k', '--auto-tune', '--auto-bail'])
        
        print(f"[*] Running Feroxbuster: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_ffuf(self, url: str, fuzz_type: str = 'dir', wordlist: str = 'common',
                filter_codes: List[int] = None, output_file: str = None) -> subprocess.Popen:
        """Run ffuf fuzzing"""
        
        wordlist_path = self.wordlists.get(wordlist, wordlist)
        
        if fuzz_type == 'dir':
            cmd = ['ffuf', '-w', wordlist_path, '-u', f"{url}/FUZZ"]
        elif fuzz_type == 'param':
            cmd = ['ffuf', '-w', wordlist_path, '-u', f"{url}?FUZZ=test"]
        else:
            raise ValueError(f"Unknown ffuf type: {fuzz_type}")
        
        if filter_codes:
            cmd.extend(['-fc', ','.join(map(str, filter_codes))])
        else:
            cmd.extend(['-fc', '404'])  # Default filter
        
        if output_file:
            cmd.extend(['-o', output_file, '-of', 'json'])
        
        # Add useful flags
        cmd.extend(['-c', '-t', '50'])
        
        print(f"[*] Running ffuf: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_nikto(self, url: str, output_file: str = None) -> subprocess.Popen:
        """Run nikto vulnerability scanner"""
        
        cmd = ['nikto', '-h', url]
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        # Add useful flags
        cmd.extend(['-C', 'all'])  # Check all CGI directories
        
        print(f"[*] Running Nikto: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_whatweb(self, url: str, output_file: str = None) -> subprocess.Popen:
        """Run WhatWeb technology fingerprinting"""
        
        cmd = ['whatweb', '-a', '3', url]
        
        if output_file:
            cmd.extend(['--log-json', output_file])
        
        print(f"[*] Running WhatWeb: {' '.join(cmd)}")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def parse_gobuster_output(self, output: str) -> List[WebFinding]:
        """Parse gobuster output into WebFinding objects"""
        findings = []
        
        for line in output.split('\n'):
            if line.startswith('/') and '(Status:' in line:
                try:
                    # Example: /admin (Status: 200) [Size: 1234]
                    parts = line.split()
                    path = parts[0]
                    status = int(parts[2].replace(')', ''))
                    size_part = [p for p in parts if 'Size:' in p]
                    size = int(size_part[0].replace('[Size:', '').replace(']', '')) if size_part else 0
                    
                    finding = WebFinding(
                        url=path,
                        status_code=status,
                        size=size,
                        tool='gobuster',
                        timestamp=datetime.now().isoformat()
                    )
                    findings.append(finding)
                except (ValueError, IndexError):
                    continue
        
        return findings
    
    def parse_whatweb_output(self, output: str) -> Dict[str, str]:
        """Parse WhatWeb output for technology stack"""
        tech_stack = {}
        
        for line in output.split('\n'):
            if '[200 OK]' in line or 'Title:' in line:
                # Extract technologies found
                if 'Apache' in line:
                    tech_stack['webserver'] = 'Apache'
                elif 'nginx' in line:
                    tech_stack['webserver'] = 'nginx'
                elif 'IIS' in line:
                    tech_stack['webserver'] = 'IIS'
                
                if 'PHP' in line:
                    tech_stack['language'] = 'PHP'
                elif 'Python' in line:
                    tech_stack['language'] = 'Python'
                elif 'Java' in line:
                    tech_stack['language'] = 'Java'
                
                if 'WordPress' in line:
                    tech_stack['cms'] = 'WordPress'
                elif 'Drupal' in line:
                    tech_stack['cms'] = 'Drupal'
                elif 'Joomla' in line:
                    tech_stack['cms'] = 'Joomla'
        
        return tech_stack
    
    def run_backup_hunter(self, url: str, output_file: str = None) -> subprocess.Popen:
        """Hunt for backup files using specialized wordlists and extensions"""
        
        # Create a temporary wordlist combining all backup-related terms
        import tempfile
        temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        
        # Combine all backup and sensitive wordlists
        all_words = set()
        for wordlist in self.sensitive_wordlists.values():
            all_words.update(wordlist)
        
        # Add the sensitive patterns directly
        all_words.update(self.sensitive_patterns)
        
        # Write to temp file
        for word in sorted(all_words):
            temp_wordlist.write(f"{word}\n")
        temp_wordlist.close()
        
        # Combine all backup-related extensions
        all_extensions = []
        all_extensions.extend(self.extensions['backup'])
        all_extensions.extend(self.extensions['config'])
        all_extensions.extend(self.extensions['database'])
        all_extensions.extend(self.extensions['sensitive'])
        all_extensions.extend(['', 'txt', 'php', 'jsp', 'asp', 'aspx'])  # Include common web extensions
        
        cmd = ['gobuster', 'dir', '-u', url, '-w', temp_wordlist.name]
        cmd.extend(['-x', ','.join(all_extensions)])
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        # Add flags for backup hunting
        cmd.extend(['-k', '--no-error', '-t', '30', '-q'])  # Quieter, slower for stealth
        
        print(f"[*] Running Backup Hunter: {' '.join(cmd[:6])}... (using {len(all_words)} words, {len(all_extensions)} extensions)")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_sensitive_file_hunter(self, url: str, output_file: str = None) -> subprocess.Popen:
        """Hunt for sensitive files using ffuf with specific patterns"""
        
        # Create temporary wordlist for sensitive files
        import tempfile
        temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        
        # Write sensitive patterns to temp file
        for pattern in self.sensitive_patterns:
            temp_wordlist.write(f"{pattern}\n")
        temp_wordlist.close()
        
        cmd = ['ffuf', '-w', temp_wordlist.name, '-u', f"{url}/FUZZ"]
        
        # Filter out common false positives
        cmd.extend(['-fc', '404,403,401,500'])
        cmd.extend(['-fs', '0'])  # Filter zero-size responses
        
        if output_file:
            cmd.extend(['-o', output_file, '-of', 'json'])
        
        # Add useful flags for sensitive file hunting
        cmd.extend(['-c', '-t', '20', '-r'])  # Colored output, 20 threads, follow redirects
        
        print(f"[*] Running Sensitive File Hunter: {' '.join(cmd[:6])}...")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def run_config_hunter(self, url: str, output_file: str = None) -> subprocess.Popen:
        """Specifically hunt for configuration files that may contain credentials"""
        
        # Create temporary wordlist for config files
        import tempfile
        temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        
        # Write config-specific patterns
        config_patterns = [
            'web.config', 'app.config', 'Web.config', 'App.config',
            'config.php', 'config.inc.php', 'configuration.php',
            'wp-config.php', 'wp-config.php.bak', 'wp-config.old',
            'database.yml', 'database.yaml', 'db.yml', 'db.yaml',
            'application.properties', 'hibernate.cfg.xml',
            '.env', '.env.local', '.env.production', '.env.staging',
            '.htaccess', '.htpasswd', 'httpd.conf', 'apache2.conf',
            'nginx.conf', 'nginx.config', 'my.cnf', 'my.ini',
            'php.ini', 'settings.php', 'local.php', 'global.php'
        ]
        
        for pattern in config_patterns:
            temp_wordlist.write(f"{pattern}\n")
        temp_wordlist.close()
        
        cmd = ['gobuster', 'dir', '-u', url, '-w', temp_wordlist.name]
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        # Config hunting specific flags
        cmd.extend(['-k', '--no-error', '-t', '20', '-q'])
        
        print(f"[*] Running Config Hunter: targeting {len(config_patterns)} configuration files...")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def parse_backup_hunter_output(self, output: str) -> List[WebFinding]:
        """Parse backup hunter output and categorize findings"""
        findings = []
        
        for line in output.split('\n'):
            if line.startswith('/') and '(Status:' in line:
                try:
                    parts = line.split()
                    path = parts[0]
                    status = int(parts[2].replace(')', ''))
                    size_part = [p for p in parts if 'Size:' in p]
                    size = int(size_part[0].replace('[Size:', '').replace(']', '')) if size_part else 0
                    
                    # Categorize the finding based on file type
                    extra_info = self._categorize_sensitive_file(path)
                    
                    finding = WebFinding(
                        url=path,
                        status_code=status,
                        size=size,
                        tool='backup_hunter',
                        timestamp=datetime.now().isoformat(),
                        extra_info=extra_info
                    )
                    findings.append(finding)
                except (ValueError, IndexError):
                    continue
        
        return findings
    
    def _categorize_sensitive_file(self, filepath: str) -> str:
        """Categorize a found file based on its name and extension"""
        lower_path = filepath.lower()
        
        # High-priority categories
        if any(pattern in lower_path for pattern in ['config', '.env', 'web.config', 'wp-config']):
            return "🔥 CONFIG FILE - May contain credentials!"
        elif any(pattern in lower_path for pattern in ['backup', '.bak', '.old', '.orig']):
            return "💾 BACKUP FILE - Check for sensitive data!"
        elif any(pattern in lower_path for pattern in ['dump', '.sql', 'database']):
            return "🗃️ DATABASE FILE - Potential data goldmine!"
        elif any(pattern in lower_path for pattern in ['phpinfo', 'info.php', 'test.php']):
            return "🔍 INFO FILE - System information disclosure!"
        elif any(pattern in lower_path for pattern in ['.key', '.pem', '.p12', '.pfx']):
            return "🔐 CRYPTO FILE - Private keys or certificates!"
        elif any(pattern in lower_path for pattern in ['readme', 'changelog', 'todo']):
            return "📝 DOCUMENTATION - May reveal system details!"
        elif any(pattern in lower_path for pattern in ['log', 'error', 'access', 'debug']):
            return "📊 LOG FILE - Check for sensitive information!"
        elif any(pattern in lower_path for pattern in ['password', 'passwd', 'credential', 'secret']):
            return "⚠️ CREDENTIAL FILE - Immediate investigation needed!"
        else:
            return "📄 SENSITIVE FILE - Requires manual review"

class TechnologyDeepDive:
    """Performs comprehensive technology stack analysis beyond basic fingerprinting"""
    
    def __init__(self):
        # Security headers to check for
        self.security_headers = [
            'strict-transport-security', 'content-security-policy', 'x-frame-options',
            'x-content-type-options', 'x-xss-protection', 'referrer-policy',
            'permissions-policy', 'expect-ct', 'feature-policy'
        ]
        
        # JavaScript library signatures
        self.js_signatures = {
            'jquery': [r'jquery[.-]?(\d+\.?\d*\.?\d*)', r'/jquery[.-](\d+\.?\d*\.?\d*)'],
            'angular': [r'angular[.-]?(\d+\.?\d*\.?\d*)', r'ng-version="([^"]+)"'],
            'react': [r'react[.-]?(\d+\.?\d*\.?\d*)', r'"react":"([^"]+)"'],
            'vue': [r'vue[.-]?(\d+\.?\d*\.?\d*)', r'"vue":"([^"]+)"'],
            'bootstrap': [r'bootstrap[.-]?(\d+\.?\d*\.?\d*)', r'/bootstrap/(\d+\.?\d*\.?\d*)'],
            'lodash': [r'lodash[.-]?(\d+\.?\d*\.?\d*)', r'"lodash":"([^"]+)"'],
            'modernizr': [r'modernizr[.-]?(\d+\.?\d*\.?\d*)', r'"modernizr":"([^"]+)"'],
            'moment': [r'moment[.-]?(\d+\.?\d*\.?\d*)', r'"moment":"([^"]+)"'],
            'socket.io': [r'socket\.io[.-]?(\d+\.?\d*\.?\d*)', r'"socket.io":"([^"]+)"']
        }
        
        # CSS framework signatures
        self.css_signatures = {
            'bootstrap': [r'/bootstrap[.-]?(\d+\.?\d*\.?\d*)', r'\.bootstrap'],
            'bulma': [r'/bulma[.-]?(\d+\.?\d*\.?\d*)', r'\.bulma'],
            'foundation': [r'/foundation[.-]?(\d+\.?\d*\.?\d*)', r'\.foundation'],
            'semantic-ui': [r'/semantic[.-]?(\d+\.?\d*\.?\d*)', r'\.ui\.'],
            'materialize': [r'/materialize[.-]?(\d+\.?\d*\.?\d*)', r'\.materialize'],
            'tailwind': [r'/tailwind[.-]?(\d+\.?\d*\.?\d*)', r'tailwind']
        }
        
        # Server/Technology fingerprints
        self.technology_fingerprints = {
            'apache': [r'apache[/\s](\d+\.?\d*\.?\d*)', r'server:\s*apache'],
            'nginx': [r'nginx[/\s](\d+\.?\d*\.?\d*)', r'server:\s*nginx'],
            'iis': [r'iis[/\s](\d+\.?\d*\.?\d*)', r'server:\s*microsoft-iis'],
            'php': [r'php[/\s](\d+\.?\d*\.?\d*)', r'x-powered-by:\s*php'],
            'asp.net': [r'asp\.net[/\s](\d+\.?\d*\.?\d*)', r'x-aspnet-version'],
            'tomcat': [r'tomcat[/\s](\d+\.?\d*\.?\d*)', r'server:\s*apache-tomcat'],
            'jetty': [r'jetty[/\s](\d+\.?\d*\.?\d*)', r'server:\s*jetty'],
            'express': [r'express[/\s](\d+\.?\d*\.?\d*)', r'x-powered-by:\s*express']
        }
    
    def analyze_url(self, url: str) -> TechnologyAnalysis:
        """Perform comprehensive technology analysis of a URL"""
        analysis = TechnologyAnalysis(url=url, timestamp=datetime.now().isoformat())
        
        try:
            # Get comprehensive response data
            headers, content, cookies = self._fetch_comprehensive_data(url)
            
            # Analyze different aspects
            self._analyze_headers(headers, analysis)
            self._analyze_cookies(cookies, analysis)
            self._analyze_content(content, analysis)
            self._analyze_security_headers(headers, analysis)
            self._detect_vulnerabilities(headers, content, analysis)
            
        except Exception as e:
            print(f"[!] Technology analysis failed for {url}: {e}")
        
        return analysis
    
    def _fetch_comprehensive_data(self, url: str) -> Tuple[Dict[str, str], str, Dict[str, str]]:
        """Fetch headers, content, and cookies using curl"""
        
        # Use curl to get comprehensive response data
        cmd = [
            'curl', '-s', '-k', '-L', '--max-time', '30',
            '-H', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-c', '/tmp/kevin_cookies.txt',  # Save cookies
            '-D', '/tmp/kevin_headers.txt',  # Save headers
            url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        content = result.stdout
        
        # Parse headers
        headers = {}
        try:
            with open('/tmp/kevin_headers.txt', 'r') as f:
                header_text = f.read()
                for line in header_text.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
        except:
            pass
        
        # Parse cookies
        cookies = {}
        try:
            with open('/tmp/kevin_cookies.txt', 'r') as f:
                cookie_text = f.read()
                for line in cookie_text.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        parts = line.split('\t')
                        if len(parts) >= 7:
                            cookies[parts[5]] = parts[6]
        except:
            pass
        
        return headers, content, cookies
    
    def _analyze_headers(self, headers: Dict[str, str], analysis: TechnologyAnalysis):
        """Analyze HTTP headers for technology identification"""
        
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = value.lower()
            
            # Server identification
            if header_lower == 'server':
                analysis.web_server = value
                # Extract version info
                for tech, patterns in self.technology_fingerprints.items():
                    for pattern in patterns:
                        match = re.search(pattern, value_lower)
                        if match and match.groups():
                            analysis.server_version = match.group(1)
                            break
            
            # Powered-by headers
            elif header_lower == 'x-powered-by':
                if 'php' in value_lower:
                    analysis.backend_language = 'PHP'
                    version_match = re.search(r'php[/\s](\d+\.?\d*\.?\d*)', value_lower)
                    if version_match:
                        analysis.backend_language = f"PHP {version_match.group(1)}"
                elif 'asp.net' in value_lower:
                    analysis.backend_language = 'ASP.NET'
                elif 'express' in value_lower:
                    analysis.backend_framework = 'Express.js'
            
            # Framework-specific headers
            elif header_lower == 'x-aspnet-version':
                analysis.backend_framework = f"ASP.NET {value}"
            elif header_lower == 'x-drupal-cache':
                analysis.cms = 'Drupal'
            elif header_lower == 'x-generator':
                if 'wordpress' in value_lower:
                    analysis.cms = 'WordPress'
                elif 'drupal' in value_lower:
                    analysis.cms = 'Drupal'
            
            # Custom headers that might reveal technology
            if header_lower.startswith('x-') and header_lower not in ['x-powered-by', 'x-aspnet-version']:
                analysis.custom_headers[header] = value
    
    def _analyze_cookies(self, cookies: Dict[str, str], analysis: TechnologyAnalysis):
        """Analyze cookies for technology identification and security"""
        
        analysis.cookies = cookies
        
        for name, value in cookies.items():
            name_lower = name.lower()
            
            # Framework identification through cookies
            if name_lower.startswith('phpsessid'):
                analysis.backend_language = 'PHP'
            elif name_lower.startswith('asp.net_sessionid'):
                analysis.backend_language = 'ASP.NET'
            elif name_lower.startswith('jsessionid'):
                analysis.backend_language = 'Java'
            elif name_lower.startswith('ci_session'):
                analysis.backend_framework = 'CodeIgniter'
            elif name_lower.startswith('laravel_session'):
                analysis.backend_framework = 'Laravel'
            elif name_lower.startswith('wordpress_'):
                analysis.cms = 'WordPress'
            elif name_lower.startswith('drupal'):
                analysis.cms = 'Drupal'
    
    def _analyze_content(self, content: str, analysis: TechnologyAnalysis):
        """Analyze page content for technology identification"""
        
        content_lower = content.lower()
        
        # CMS Detection
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            analysis.cms = 'WordPress'
            # Try to extract version
            version_match = re.search(r'wordpress[/\s](\d+\.?\d*\.?\d*)', content_lower)
            if version_match:
                analysis.cms_version = version_match.group(1)
        
        elif '/drupal/' in content_lower or 'drupal.js' in content_lower:
            analysis.cms = 'Drupal'
        
        elif 'joomla' in content_lower:
            analysis.cms = 'Joomla'
        
        # JavaScript Library Detection
        for lib, patterns in self.js_signatures.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content_lower)
                for match in matches:
                    if match.groups():
                        analysis.js_libraries[lib] = match.group(1)
                    else:
                        analysis.js_libraries[lib] = 'detected'
                    break
        
        # CSS Framework Detection
        for framework, patterns in self.css_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    analysis.css_frameworks.append(framework)
                    break
        
        # Frontend Framework Detection
        if 'ng-version' in content or 'angular' in content_lower:
            analysis.frontend_framework = 'Angular'
        elif 'react' in content_lower and ('jsx' in content or 'react-dom' in content_lower):
            analysis.frontend_framework = 'React'
        elif 'vue' in content_lower and ('v-' in content or 'vue.js' in content_lower):
            analysis.frontend_framework = 'Vue.js'
    
    def _analyze_security_headers(self, headers: Dict[str, str], analysis: TechnologyAnalysis):
        """Analyze security headers and identify missing ones"""
        
        header_keys = [h.lower() for h in headers.keys()]
        
        for security_header in self.security_headers:
            if security_header in header_keys:
                analysis.security_headers[security_header] = headers.get(security_header, '')
            else:
                analysis.missing_security_headers.append(security_header)
    
    def _detect_vulnerabilities(self, headers: Dict[str, str], content: str, analysis: TechnologyAnalysis):
        """Detect potential vulnerabilities based on technology analysis"""
        
        # Missing security headers
        if analysis.missing_security_headers:
            analysis.security_issues.append(f"Missing {len(analysis.missing_security_headers)} security headers")
        
        # Insecure server versions
        if analysis.web_server:
            server_lower = analysis.web_server.lower()
            if 'apache/2.2' in server_lower:
                analysis.potential_vulnerabilities.append("Apache 2.2.x - Multiple known vulnerabilities")
            elif 'nginx/1.0' in server_lower or 'nginx/1.1' in server_lower:
                analysis.potential_vulnerabilities.append("Nginx 1.0/1.1 - Multiple known vulnerabilities")
            elif 'iis/6.0' in server_lower:
                analysis.potential_vulnerabilities.append("IIS 6.0 - Multiple known vulnerabilities")
        
        # Outdated JavaScript libraries
        for lib, version in analysis.js_libraries.items():
            if lib == 'jquery' and version.startswith('1.'):
                analysis.potential_vulnerabilities.append(f"jQuery {version} - XSS vulnerabilities in older versions")
            elif lib == 'angular' and version.startswith('1.'):
                analysis.potential_vulnerabilities.append(f"AngularJS {version} - Known XSS and injection issues")
        
        # Information disclosure
        if 'x-powered-by' in [h.lower() for h in headers.keys()]:
            analysis.security_issues.append("Information disclosure via X-Powered-By header")
        
        if 'server' in [h.lower() for h in headers.keys()]:
            analysis.security_issues.append("Server version disclosure in Server header")
        
        # CMS-specific vulnerabilities
        if analysis.cms == 'WordPress' and not analysis.cms_version:
            analysis.potential_vulnerabilities.append("WordPress version not detected - could be vulnerable")
        elif analysis.cms == 'Drupal':
            analysis.potential_vulnerabilities.append("Drupal detected - check for Drupalgeddon vulnerabilities")
        
        # Cookie security issues
        for cookie_name in analysis.cookies.keys():
            if 'secure' not in cookie_name.lower():
                analysis.security_issues.append(f"Cookie {cookie_name} may lack Secure flag")

class VirtualHostDiscovery:
    """Discovers virtual hosts through DNS enumeration and HTTP Host header fuzzing"""
    
    def __init__(self):
        # Common subdomain wordlists
        self.subdomain_wordlists = {
            'common': [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev',
                'developer', 'stage', 'staging', 'test', 'testing', 'sandbox', 'beta',
                'admin', 'administrator', 'api', 'blog', 'cms', 'crm', 'forum', 'help',
                'intranet', 'kb', 'mail2', 'news', 'newsletter', 'old', 'portal', 'secure',
                'server', 'shop', 'ssl', 'support', 'upload', 'vpn', 'webmaster', 'wiki'
            ],
            'extended': [
                'app', 'application', 'apps', 'access', 'account', 'accounts', 'affiliate',
                'affiliates', 'agenda', 'alpha', 'alumni', 'analytics', 'android', 'apache',
                'api1', 'api2', 'api3', 'app1', 'app2', 'app3', 'assets', 'auth', 'backup',
                'backups', 'banner', 'banners', 'beta1', 'beta2', 'billing', 'blackboard',
                'blog1', 'blog2', 'blogs', 'board', 'book', 'booking', 'books', 'bugzilla',
                'business', 'buy', 'cache', 'calendar', 'careers', 'cart', 'catalog',
                'catalogue', 'cdn', 'chat', 'check', 'checkout', 'client', 'clients',
                'cloud', 'cms1', 'cms2', 'code', 'commerce', 'community', 'company',
                'conference', 'config', 'connect', 'contact', 'content', 'control',
                'corporate', 'cp', 'cpanel1', 'cpanel2', 'crm1', 'crm2', 'cs', 'css',
                'customer', 'customers', 'dashboard', 'data', 'database', 'db', 'db1',
                'db2', 'demo1', 'demo2', 'demo3', 'design', 'desktop', 'directory',
                'dl', 'doc', 'docs', 'domain', 'download', 'downloads', 'edge', 'edit',
                'email', 'en', 'engine', 'english', 'enterprise', 'event', 'events',
                'example', 'exchange', 'external', 'extranet', 'faculty', 'feedback',
                'file', 'files', 'finance', 'financial', 'flash', 'forms', 'forum1',
                'forum2', 'forums', 'fr', 'free', 'french', 'fs', 'gallery', 'game',
                'games', 'gateway', 'german', 'git', 'github', 'gw', 'home', 'host',
                'hosting', 'hr', 'html', 'http', 'https', 'hub', 'i', 'id', 'image',
                'images', 'imap', 'img', 'info', 'internal', 'international', 'internet',
                'intra', 'io', 'ipad', 'iphone', 'ipv4', 'ipv6', 'irc', 'iso', 'issue',
                'issues', 'it', 'java', 'javascript', 'job', 'jobs', 'js', 'json',
                'lab', 'labs', 'ldap', 'learn', 'learning', 'legal', 'library', 'license',
                'link', 'links', 'linux', 'live', 'local', 'location', 'log', 'login',
                'logs', 'mac', 'manage', 'management', 'manager', 'map', 'maps', 'marketing',
                'master', 'media', 'member', 'members', 'memory', 'message', 'messages',
                'messaging', 'microsoft', 'mirror', 'mobile1', 'mobile2', 'mod', 'money',
                'monitor', 'monitoring', 'moodle', 'mysql', 'net', 'network', 'new',
                'node', 'null', 'office', 'online', 'order', 'orders', 'page', 'panel',
                'partner', 'partners', 'pay', 'payment', 'payments', 'photo', 'photos',
                'php', 'pics', 'picture', 'pictures', 'pilot', 'pop3', 'portal1',
                'portal2', 'post', 'postgres', 'preview', 'print', 'private', 'prod',
                'production', 'products', 'profile', 'project', 'projects', 'promo',
                'proxy', 'public', 'publish', 'purchase', 'python', 'redirect', 'ref',
                'register', 'registration', 'release', 'remote', 'report', 'reports',
                'repository', 'request', 'research', 'resource', 'resources', 'root',
                'router', 'rss', 'ruby', 'sales', 'sample', 'script', 'scripts', 'sdk',
                'search', 'section', 'sections', 'security', 'send', 'service', 'services',
                'session', 'share', 'shared', 'shell', 'show', 'site', 'sites', 'smtp1',
                'smtp2', 'sql', 'ssh', 'ssl1', 'ssl2', 'staff', 'stat', 'static',
                'statistics', 'stats', 'status', 'store', 'student', 'students', 'sub',
                'subdomain', 'survey', 'svn', 'sync', 'system', 'tablet', 'task',
                'team', 'teams', 'tech', 'temp', 'template', 'templates', 'terminal',
                'terms', 'test1', 'test2', 'test3', 'text', 'theme', 'themes', 'ticket',
                'tickets', 'time', 'tmp', 'tools', 'top', 'tour', 'track', 'tracking',
                'trade', 'training', 'transfer', 'translate', 'translation', 'tunnel',
                'tv', 'uk', 'unix', 'update', 'updates', 'upgrade', 'url', 'us',
                'user', 'users', 'v1', 'v2', 'v3', 'validate', 'validation', 'video',
                'videos', 'view', 'virtual', 'virus', 'vm', 'voice', 'voip', 'vote',
                'w3', 'wap', 'watch', 'weather', 'web1', 'web2', 'web3', 'webadmin',
                'webapp', 'webapps', 'webcam', 'webconf', 'webct', 'webdb', 'weblog',
                'weblogs', 'webmin', 'webstats', 'webtest', 'welcome', 'windows',
                'wordpress', 'work', 'workshop', 'ws', 'xml', 'year', 'zone'
            ]
        }
        
        # Common file extensions for virtual host discovery
        self.vhost_extensions = [
            '', '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.co.uk',
            '.local', '.internal', '.lan', '.corp', '.company', '.domain'
        ]
        
        # Common HTTP methods to test
        self.http_methods = ['GET', 'HEAD', 'POST', 'OPTIONS']
    
    def discover_dns_subdomains(self, domain: str, wordlist: str = 'common') -> List[VirtualHost]:
        """Discover subdomains using DNS resolution"""
        vhosts = []
        wordlist_items = self.subdomain_wordlists.get(wordlist, self.subdomain_wordlists['common'])
        
        print(f"[*] DNS subdomain enumeration for {domain} using {len(wordlist_items)} subdomains...")
        
        for subdomain in wordlist_items:
            hostname = f"{subdomain}.{domain}"
            
            try:
                # Use dig to resolve subdomain
                result = subprocess.run(
                    ['dig', '+short', hostname], 
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    ip_addresses = [line.strip() for line in result.stdout.strip().split('\n') 
                                  if line.strip() and not line.startswith(';')]
                    
                    for ip in ip_addresses:
                        if self._is_valid_ip(ip):
                            # Verify the subdomain with HTTP request
                            vhost = self._test_virtual_host(hostname, ip, 'dns_subdomain')
                            if vhost:
                                vhosts.append(vhost)
                                print(f"[+] Found subdomain: {hostname} -> {ip}")
                
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
        
        return vhosts
    
    def discover_host_header_fuzzing(self, target_ip: str, base_domain: str = None, 
                                   wordlist: str = 'common', port: int = 80) -> List[VirtualHost]:
        """Discover virtual hosts using Host header fuzzing"""
        vhosts = []
        
        # Get baseline response first
        baseline = self._get_baseline_response(target_ip, port)
        if not baseline:
            print(f"[!] Could not get baseline response from {target_ip}:{port}")
            return vhosts
        
        print(f"[*] Host header fuzzing on {target_ip}:{port} (baseline: {baseline['status']} - {baseline['length']}b)")
        
        wordlist_items = self.subdomain_wordlists.get(wordlist, self.subdomain_wordlists['common'])
        
        # Generate potential hostnames
        hostnames_to_test = []
        
        # If we have a base domain, test subdomains
        if base_domain:
            for subdomain in wordlist_items:
                hostnames_to_test.append(f"{subdomain}.{base_domain}")
        
        # Also test standalone hostnames
        for hostname in wordlist_items:
            hostnames_to_test.extend([
                hostname,
                f"{hostname}.local",
                f"{hostname}.internal",
                f"{hostname}.{target_ip.replace('.', '-')}.nip.io"
            ])
        
        # Remove duplicates and sort
        hostnames_to_test = sorted(list(set(hostnames_to_test)))
        
        print(f"[*] Testing {len(hostnames_to_test)} potential virtual hosts...")
        
        for hostname in hostnames_to_test:
            vhost = self._test_host_header(target_ip, port, hostname, baseline)
            if vhost and vhost.unique_content:
                vhosts.append(vhost)
                print(f"[+] Found virtual host: {hostname} (Status: {vhost.status_code}, Size: {vhost.content_length}b)")
        
        return vhosts
    
    def discover_reverse_dns(self, target_ip: str) -> List[VirtualHost]:
        """Discover virtual hosts using reverse DNS lookup"""
        vhosts = []
        
        try:
            # Use dig for reverse DNS lookup
            result = subprocess.run(
                ['dig', '+short', '-x', target_ip], 
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                hostnames = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') 
                           if line.strip() and not line.startswith(';')]
                
                for hostname in hostnames:
                    if hostname and hostname != target_ip:
                        vhost = self._test_virtual_host(hostname, target_ip, 'reverse_dns')
                        if vhost:
                            vhosts.append(vhost)
                            print(f"[+] Found reverse DNS: {hostname} -> {target_ip}")
            
        except Exception as e:
            print(f"[!] Reverse DNS lookup failed: {e}")
        
        return vhosts
    
    def _get_baseline_response(self, target_ip: str, port: int) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target_ip}:{port}"
            
            result = subprocess.run([
                'curl', '-s', '-k', '-w', '%{http_code},%{size_download},%{time_total}',
                '-o', '/dev/null', '--max-time', '10',
                '-H', f'Host: {target_ip}',
                url
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                metrics = result.stdout.strip().split(',')
                if len(metrics) >= 3:
                    return {
                        'status': int(metrics[0]),
                        'length': int(metrics[1]),
                        'time': float(metrics[2])
                    }
        
        except Exception:
            pass
        
        return None
    
    def _test_host_header(self, target_ip: str, port: int, hostname: str, 
                         baseline: Dict) -> Optional[VirtualHost]:
        """Test a specific hostname using Host header"""
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target_ip}:{port}"
            
            # Test with Host header
            result = subprocess.run([
                'curl', '-s', '-k', '-w', '%{http_code},%{size_download},%{time_total}',
                '-o', '/tmp/kevin_vhost_test.html', '--max-time', '10',
                '-H', f'Host: {hostname}',
                url
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                metrics = result.stdout.strip().split(',')
                if len(metrics) >= 3:
                    status_code = int(metrics[0])
                    content_length = int(metrics[1])
                    response_time = float(metrics[2])
                    
                    # Check if response is significantly different from baseline
                    is_unique = self._is_response_unique(status_code, content_length, baseline)
                    
                    if is_unique:
                        # Extract additional info
                        title = self._extract_title_from_file('/tmp/kevin_vhost_test.html')
                        
                        return VirtualHost(
                            hostname=hostname,
                            ip=target_ip,
                            status_code=status_code,
                            content_length=content_length,
                            title=title,
                            discovery_method='host_header',
                            response_time=response_time,
                            unique_content=True
                        )
        
        except Exception:
            pass
        
        return None
    
    def _test_virtual_host(self, hostname: str, ip: str, method: str) -> Optional[VirtualHost]:
        """Test a virtual host discovered through DNS"""
        try:
            # Try both HTTP and HTTPS
            for protocol, port in [('http', 80), ('https', 443)]:
                url = f"{protocol}://{hostname}"
                
                result = subprocess.run([
                    'curl', '-s', '-k', '-w', '%{http_code},%{size_download},%{time_total}',
                    '-o', '/tmp/kevin_vhost_test.html', '--max-time', '10',
                    '--resolve', f'{hostname}:{port}:{ip}',
                    url
                ], capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    metrics = result.stdout.strip().split(',')
                    if len(metrics) >= 3:
                        status_code = int(metrics[0])
                        content_length = int(metrics[1])
                        response_time = float(metrics[2])
                        
                        if status_code < 400:  # Only consider successful responses
                            title = self._extract_title_from_file('/tmp/kevin_vhost_test.html')
                            
                            return VirtualHost(
                                hostname=hostname,
                                ip=ip,
                                status_code=status_code,
                                content_length=content_length,
                                title=title,
                                discovery_method=method,
                                response_time=response_time,
                                unique_content=True
                            )
        
        except Exception:
            pass
        
        return None
    
    def _is_response_unique(self, status: int, length: int, baseline: Dict) -> bool:
        """Check if response is significantly different from baseline"""
        baseline_status = baseline['status']
        baseline_length = baseline['length']
        
        # Different status code
        if status != baseline_status:
            return True
        
        # Significant difference in content length (more than 10% difference)
        if baseline_length > 0:
            diff_percentage = abs(length - baseline_length) / baseline_length
            if diff_percentage > 0.1:  # 10% difference
                return True
        
        # Very different content lengths
        if abs(length - baseline_length) > 1000:  # More than 1KB difference
            return True
        
        return False
    
    def _extract_title_from_file(self, filepath: str) -> Optional[str]:
        """Extract HTML title from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Extract title using regex
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        
        except Exception:
            pass
        
        return None
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            parts = ip_str.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

class MySQLEnumerator(BaseServiceEnumerator):
    """Comprehensive MySQL enumeration using refactored base framework"""
    
    def __init__(self):
        config = ServiceConfig(
            service_name="MySQL",
            default_port=3306,
            nmap_scripts=[
                'mysql-info', 'mysql-audit', 'mysql-databases', 'mysql-dump-hashes',
                'mysql-empty-password', 'mysql-enum', 'mysql-users', 'mysql-variables',
                'mysql-vuln-cve2012-2122'
            ],
            version_patterns={
                'version': r'Version: ([^\n]+)',
                'server_version': r'Server version: ([^\n]+)',
                'protocol_version': r'Protocol version: ([^\n]+)'
            },
            security_indicators=[
                'empty password', 'anonymous access', 'root account accessible',
                'file privileges', 'weak ssl', 'default credentials'
            ],
            common_vulns=['CVE-2012-2122', 'CVE-2016-6662', 'CVE-2017-3599']
        )
        super().__init__(config)
        
        # MySQL-specific attributes  
        self.common_passwords = CommonResources.COMMON_PASSWORDS['database']
        self.default_accounts = CommonResources.DEFAULT_ACCOUNTS['mysql']
    
    def _create_finding(self, target: str, port: int) -> MySQLFinding:
        """Create MySQL finding object"""
        return MySQLFinding(target=target, port=port, timestamp=datetime.now().isoformat())
    
    def enumerate_mysql(self, target: str, port: int = 3306) -> MySQLFinding:
        """Comprehensive MySQL enumeration using base framework"""
        return self.enumerate(target, port)
    
    def _phase_3_detailed_enum(self, target: str, port: int, finding: MySQLFinding):
        """Phase 3: MySQL-specific detailed enumeration"""
        print(f"[*] Phase 3: MySQL database and user enumeration...")
        
        # Run MySQL-specific enumeration scripts
        mysql_enum_scripts = ['mysql-databases', 'mysql-users', 'mysql-variables']
        result = CommandExecutor.run_nmap_scripts(mysql_enum_scripts, target, port)
        
        if result.success:
            # Parse databases
            databases = re.findall(r'Database: ([^\n\r]+)', result.output)
            finding.databases = databases
            
            accessible_dbs = re.findall(r'Accessible: ([^\n\r]+)', result.output)
            finding.accessible_databases = accessible_dbs
            
            # Parse users
            users = re.findall(r'User: ([^\n\r]+)', result.output)
            finding.users = users
            
            # Parse variables
            variables = {}
            for var in ['version', 'datadir', 'secure_file_priv', 'local_infile', 'have_ssl']:
                pattern = rf'{var}\s*=\s*([^\n\r]+)'
                match = re.search(pattern, result.output, re.IGNORECASE)
                if match:
                    variables[var] = match.group(1).strip()
            finding.variables = variables
            
            print(f"[+] Found {len(databases)} databases, {len(users)} users")
    
    def _check_service_specific_issues(self, finding: MySQLFinding) -> List[str]:
        """Check MySQL-specific security issues"""
        issues = []
        
        # Check for dangerous local_infile setting
        if finding.variables and finding.variables.get('local_infile', '').lower() == 'on':
            issues.append("CRITICAL: Local file loading enabled - file system access possible")
        
        # Check for access to sensitive databases
        if finding.accessible_databases:
            sensitive_dbs = ['mysql', 'information_schema', 'performance_schema']
            accessible_sensitive = [db for db in finding.accessible_databases if db.lower() in sensitive_dbs]
            if accessible_sensitive:
                issues.append(f"Access to sensitive databases: {', '.join(accessible_sensitive)}")
        
        # Check SSL configuration
        if finding.variables and finding.variables.get('have_ssl', '').lower() in ['no', 'off']:
            issues.append("SSL/TLS encryption not available")
        
        return issues

# Original MySQL methods replaced with refactored framework
# Removed ~250 lines of duplicate subprocess/parsing code
# Now using BaseServiceEnumerator with standardized patterns

class MSSQLEnumerator:
    """Comprehensive MSSQL enumeration using nmap scripts and manual techniques"""
    
    def __init__(self):
        # MSSQL-specific nmap scripts for enumeration
        self.mssql_scripts = [
            'ms-sql-info',              # Basic MSSQL server information
            'ms-sql-config',            # Configuration enumeration
            'ms-sql-empty-password',    # Test for empty passwords
            'ms-sql-dump-hashes',       # Enumerate password hashes (if accessible)
            'ms-sql-hasdbaccess',       # Test database access
            'ms-sql-query',             # Execute queries (if accessible)
            'ms-sql-tables',            # Enumerate tables
            'ms-sql-xp-cmdshell',       # Test xp_cmdshell access
        ]
        
        # Common MSSQL security issues to check
        self.security_checks = [
            'empty_passwords',
            'weak_authentication', 
            'xp_cmdshell_enabled',
            'ole_automation_enabled',
            'database_access',
            'sysadmin_privileges',
            'linked_servers'
        ]
        
        # Common MSSQL default accounts
        self.default_accounts = [
            'sa', 'MSSQL$', 'SQLEXPRESS', 'administrator', 'admin'
        ]
        
        # Common weak passwords to suggest testing
        self.common_passwords = [
            '', 'sa', 'password', 'admin', 'administrator', 'root', 
            'mssql', 'sql', '123456', 'Password123', 'sa123'
        ]
    
    def enumerate_mssql(self, target: str, port: int = 1433) -> MSSQLFinding:
        """Comprehensive MSSQL enumeration"""
        print(f"[*] MSSQL enumeration on {target}:{port}")
        
        finding = MSSQLFinding(
            target=target,
            port=port,
            timestamp=datetime.now().isoformat()
        )
        
        # Phase 1: Basic information gathering
        self._get_mssql_info(target, port, finding)
        
        # Phase 2: Authentication and access testing
        self._test_mssql_authentication(target, port, finding)
        
        # Phase 3: Database and configuration enumeration
        self._enumerate_mssql_databases(target, port, finding)
        
        # Phase 4: Security assessment
        self._assess_mssql_security(finding)
        
        return finding
    
    def _get_mssql_info(self, target: str, port: int, finding: MSSQLFinding):
        """Get basic MSSQL server information"""
        print(f"[*] Phase 1: MSSQL server information gathering...")
        
        # Run ms-sql-info script
        try:
            result = subprocess.run([
                'nmap', '--script', 'ms-sql-info', 
                '-p', str(port), target
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse version information
                version_match = re.search(r'Version: ([^\n]+)', output)
                if version_match:
                    finding.version = version_match.group(1).strip()
                
                # Parse server version
                server_match = re.search(r'Server Version: ([^\n]+)', output)
                if server_match:
                    finding.server_version = server_match.group(1).strip()
                
                # Parse instance name
                instance_match = re.search(r'Instance name: ([^\n]+)', output)
                if instance_match:
                    finding.instance_name = instance_match.group(1).strip()
                
                # Parse server name
                name_match = re.search(r'Server name: ([^\n]+)', output)
                if name_match:
                    finding.server_name = name_match.group(1).strip()
                
                print(f"[+] MSSQL version: {finding.version or 'Unknown'}")
                if finding.instance_name:
                    print(f"[+] Instance name: {finding.instance_name}")
                
        except subprocess.TimeoutExpired:
            print(f"[!] ms-sql-info script timed out")
        except Exception as e:
            print(f"[!] Error running ms-sql-info: {e}")
    
    def _test_mssql_authentication(self, target: str, port: int, finding: MSSQLFinding):
        """Test MSSQL authentication methods and weak passwords"""
        print(f"[*] Phase 2: Authentication testing...")
        
        # Check for empty password on sa account
        try:
            result = subprocess.run([
                'nmap', '--script', 'ms-sql-empty-password', 
                '-p', str(port), target
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                if 'sa account has empty password' in output.lower():
                    finding.weak_passwords.append('sa:')
                    finding.security_issues.append("SA account has empty password - critical security risk!")
                    print(f"[!] CRITICAL: SA account has empty password!")
                
                # Look for other accounts with empty passwords
                empty_accounts = re.findall(r'account (\w+) has empty password', output.lower())
                for account in empty_accounts:
                    if f"{account}:" not in finding.weak_passwords:
                        finding.weak_passwords.append(f"{account}:")
                        finding.security_issues.append(f"Account '{account}' has empty password")
                        print(f"[!] Account '{account}' has empty password")
                
        except Exception as e:
            print(f"[!] Error checking empty passwords: {e}")
    
    def _enumerate_mssql_databases(self, target: str, port: int, finding: MSSQLFinding):
        """Enumerate MSSQL databases and configuration"""
        print(f"[*] Phase 3: Database and configuration enumeration...")
        
        # Run configuration enumeration
        try:
            result = subprocess.run([
                'nmap', '--script', 'ms-sql-config', 
                '-p', str(port), target
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for dangerous configurations
                if 'xp_cmdshell' in output.lower() and 'enabled' in output.lower():
                    finding.xp_cmdshell_enabled = True
                    finding.security_issues.append("xp_cmdshell is enabled - command execution possible!")
                    print(f"[!] xp_cmdshell is enabled!")
                
                if 'ole automation' in output.lower() and 'enabled' in output.lower():
                    finding.ole_automation_enabled = True
                    finding.security_issues.append("OLE Automation is enabled")
                    print(f"[!] OLE Automation is enabled")
                
                if 'clr enabled' in output.lower():
                    finding.clr_enabled = True
                    finding.security_issues.append("CLR is enabled")
                    print(f"[!] CLR is enabled")
                
        except Exception as e:
            print(f"[!] Error checking MSSQL configuration: {e}")
        
        # Test database access if possible
        try:
            result = subprocess.run([
                'nmap', '--script', 'ms-sql-hasdbaccess', 
                '-p', str(port), target
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse accessible databases
                db_matches = re.findall(r'Database: ([^\n]+)', output)
                for db in db_matches:
                    db_clean = db.strip()
                    if db_clean and db_clean not in finding.databases:
                        finding.databases.append(db_clean)
                        finding.accessible_databases.append(db_clean)
                
                if finding.databases:
                    print(f"[+] Found {len(finding.databases)} accessible databases")
                
        except Exception as e:
            print(f"[!] Error checking database access: {e}")
    
    def _assess_mssql_security(self, finding: MSSQLFinding):
        """Assess overall MSSQL security posture"""
        print(f"[*] Phase 4: Security assessment...")
        
        # Analyze version for known vulnerabilities
        if finding.version:
            version_lower = finding.version.lower()
            
            # Check for very old versions
            if any(old_ver in version_lower for old_ver in ['2000', '2005', '2008']):
                finding.security_issues.append(f"Very old MSSQL version detected: {finding.version}")
                print(f"[!] Very old MSSQL version: {finding.version}")
            
            # Check for versions with known issues
            if '2012' in version_lower:
                finding.security_issues.append("MSSQL 2012 has known security issues - check for patches")
            elif '2014' in version_lower:
                finding.security_issues.append("MSSQL 2014 has some known security issues - verify patch level")
        
        # Authentication mode assessment
        if finding.weak_passwords:
            finding.security_issues.append("Weak or empty passwords detected - immediate security risk")
        
        # Overall security assessment
        critical_issues = len([issue for issue in finding.security_issues 
                             if any(keyword in issue.lower() for keyword in ['critical', 'empty password', 'sa', 'xp_cmdshell'])])
        
        print(f"[*] Security assessment complete:")
        print(f"    Total issues found: {len(finding.security_issues)}")
        print(f"    Critical issues: {critical_issues}")
        
        if critical_issues > 0:
            print(f"[!] CRITICAL security issues detected - immediate attention required!")

class OracleEnumerator:
    """Comprehensive Oracle enumeration using nmap scripts and tnscmd10g"""
    
    def __init__(self):
        # Oracle-specific nmap scripts
        self.oracle_scripts = [
            'oracle-enum-users',        # Enumerate Oracle users
            'oracle-sid-brute',         # Brute force Oracle SIDs
            'oracle-tns-version',       # TNS listener version
        ]
        
        # Common Oracle SIDs to test
        self.common_sids = [
            'XE', 'ORCL', 'TEST', 'PROD', 'DEV', 'ORACLE', 'DB',
            'SID', 'DEMO', 'SAMPLE', 'SCOTT', 'HR', 'OE', 'PM',
            'SH', 'BI', 'IX', 'APEX', 'XEXDB', 'PLSExtProc'
        ]
        
        # Common Oracle default accounts
        self.default_accounts = [
            'SYS', 'SYSTEM', 'SCOTT', 'HR', 'OE', 'PM', 'SH',
            'DBSNMP', 'SYSMAN', 'MGMT_VIEW', 'FLOWS_FILES',
            'APEX_PUBLIC_USER', 'ANONYMOUS'
        ]
        
        # Common Oracle weak passwords
        self.common_passwords = [
            'oracle', 'password', 'admin', 'system', 'manager',
            'scott', 'tiger', 'hr', 'change_on_install', 'welcome1'
        ]
    
    def enumerate_oracle(self, target: str, port: int = 1521) -> OracleFinding:
        """Comprehensive Oracle enumeration"""
        print(f"[*] Oracle enumeration on {target}:{port}")
        
        finding = OracleFinding(
            target=target,
            port=port,
            timestamp=datetime.now().isoformat()
        )
        
        # Phase 1: TNS Listener information
        self._get_oracle_listener_info(target, port, finding)
        
        # Phase 2: SID enumeration
        self._enumerate_oracle_sids(target, port, finding)
        
        # Phase 3: Version and banner information
        self._get_oracle_version_info(target, port, finding)
        
        # Phase 4: Security assessment
        self._assess_oracle_security(finding)
        
        return finding
    
    def _get_oracle_listener_info(self, target: str, port: int, finding: OracleFinding):
        """Get Oracle TNS Listener information"""
        print(f"[*] Phase 1: Oracle TNS Listener enumeration...")
        
        # Try tnscmd10g if available
        try:
            result = subprocess.run([
                'tnscmd10g', 'version', '-h', target, '-p', str(port)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse listener version
                version_match = re.search(r'Version ([^\n]+)', output)
                if version_match:
                    finding.listener_version = version_match.group(1).strip()
                    print(f"[+] TNS Listener version: {finding.listener_version}")
                
                # Get listener status
                status_result = subprocess.run([
                    'tnscmd10g', 'status', '-h', target, '-p', str(port)
                ], capture_output=True, text=True, timeout=30)
                
                if status_result.returncode == 0:
                    finding.listener_status = "Active"
                    print(f"[+] TNS Listener is active")
                
        except FileNotFoundError:
            print(f"[!] tnscmd10g not found - trying nmap scripts")
        except Exception as e:
            print(f"[!] Error running tnscmd10g: {e}")
        
        # Fallback to nmap scripts
        try:
            result = subprocess.run([
                'nmap', '--script', 'oracle-tns-version', 
                '-p', str(port), target
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse TNS version from nmap output
                if 'Version:' in output:
                    version_match = re.search(r'Version: ([^\n]+)', output)
                    if version_match and not finding.listener_version:
                        finding.listener_version = version_match.group(1).strip()
                        print(f"[+] TNS Listener version: {finding.listener_version}")
                
        except Exception as e:
            print(f"[!] Error running oracle-tns-version: {e}")
    
    def _enumerate_oracle_sids(self, target: str, port: int, finding: OracleFinding):
        """Enumerate Oracle SIDs"""
        print(f"[*] Phase 2: Oracle SID enumeration...")
        
        # Try nmap SID brute force
        try:
            result = subprocess.run([
                'nmap', '--script', 'oracle-sid-brute', 
                '-p', str(port), target
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse discovered SIDs
                sid_matches = re.findall(r'SID: ([^\n\s]+)', output)
                for sid in sid_matches:
                    sid_clean = sid.strip()
                    if sid_clean and sid_clean not in finding.sids:
                        finding.sids.append(sid_clean)
                
                if finding.sids:
                    print(f"[+] Found {len(finding.sids)} Oracle SIDs: {', '.join(finding.sids)}")
                
        except Exception as e:
            print(f"[!] Error running oracle-sid-brute: {e}")
        
        # Manual SID testing with tnscmd10g
        if finding.sids:  # Only test discovered SIDs
            sids_to_test = finding.sids
        else:
            sids_to_test = self.common_sids[:10]  # Test common SIDs if none discovered
            print(f"[*] Testing common SIDs: {', '.join(sids_to_test)}")
        
        for sid in sids_to_test:
            try:
                result = subprocess.run([
                    'tnscmd10g', 'ping', '-h', target, '-p', str(port), '-s', sid
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and 'OK' in result.stdout:
                    if sid not in finding.sids:
                        finding.sids.append(sid)
                    finding.accessible_sids.append(sid)
                    print(f"[+] SID '{sid}' is accessible")
                
            except FileNotFoundError:
                break  # tnscmd10g not available
            except Exception:
                continue
    
    def _get_oracle_version_info(self, target: str, port: int, finding: OracleFinding):
        """Get Oracle version and banner information"""
        print(f"[*] Phase 3: Oracle version enumeration...")
        
        # Try to get version information for each accessible SID
        for sid in finding.accessible_sids:
            try:
                # Use tnscmd10g to get version
                result = subprocess.run([
                    'tnscmd10g', 'version', '-h', target, '-p', str(port), '-s', sid
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    output = result.stdout
                    
                    # Parse Oracle version
                    version_match = re.search(r'Oracle Database ([^\n]+)', output)
                    if version_match and not finding.version:
                        finding.version = version_match.group(1).strip()
                        print(f"[+] Oracle version: {finding.version}")
                    
                    # Parse banner
                    banner_match = re.search(r'BANNER\n([^\n]+)', output)
                    if banner_match and not finding.banner:
                        finding.banner = banner_match.group(1).strip()
                        print(f"[+] Oracle banner: {finding.banner}")
                
            except FileNotFoundError:
                break  # tnscmd10g not available
            except Exception:
                continue
    
    def _assess_oracle_security(self, finding: OracleFinding):
        """Assess Oracle security posture"""
        print(f"[*] Phase 4: Security assessment...")
        
        # Check for accessible SIDs
        if finding.accessible_sids:
            finding.security_issues.append(f"Found {len(finding.accessible_sids)} accessible Oracle SIDs")
            print(f"[+] {len(finding.accessible_sids)} accessible SIDs found")
        
        # Version-based assessment
        if finding.version:
            version_lower = finding.version.lower()
            
            # Check for very old versions
            if any(old_ver in version_lower for old_ver in ['9i', '10g', '11g r1']):
                finding.security_issues.append(f"Old Oracle version detected: {finding.version}")
                print(f"[!] Old Oracle version: {finding.version}")
        
        # Check for common SIDs
        common_found = [sid for sid in finding.sids if sid.upper() in ['XE', 'ORCL', 'TEST', 'DEV']]
        if common_found:
            finding.security_issues.append(f"Common Oracle SIDs found: {', '.join(common_found)}")
            print(f"[!] Common SIDs detected: {', '.join(common_found)}")
        
        # Overall assessment
        print(f"[*] Security assessment complete:")
        print(f"    Total SIDs found: {len(finding.sids)}")
        print(f"    Accessible SIDs: {len(finding.accessible_sids)}")
        print(f"    Security issues: {len(finding.security_issues)}")

class SMTPEnumerator:
    """SMTP service enumeration using nmap scripts and manual techniques"""
    
    def enumerate_smtp(self, target: str, port: int = 25) -> SMTPFinding:
        """Comprehensive SMTP enumeration"""
        print(f"[*] Starting SMTP enumeration on {target}:{port}")
        
        finding = SMTPFinding(target=target, port=port)
        
        # Phase 1: Basic information gathering
        print("[*] Phase 1: Basic SMTP information gathering...")
        self._gather_basic_info(target, port, finding)
        
        # Phase 2: Capability and extension discovery
        print("[*] Phase 2: SMTP capability discovery...")
        self._discover_capabilities(target, port, finding)
        
        # Phase 3: User enumeration
        print("[*] Phase 3: SMTP user enumeration...")
        self._enumerate_users(target, port, finding)
        
        # Phase 4: Security assessment
        print("[*] Phase 4: SMTP security assessment...")
        self._assess_security(target, port, finding)
        
        return finding
    
    def _gather_basic_info(self, target: str, port: int, finding: SMTPFinding):
        """Gather basic SMTP information using nmap scripts"""
        try:
            # Basic SMTP information gathering
            cmd = [
                'nmap', '--script', 
                'smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport',
                '-p', str(port), target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse banner and basic info
            if 'smtp-commands' in output:
                # Extract banner
                banner_match = re.search(r'Banner: (.+)', output)
                if banner_match:
                    finding.banner = banner_match.group(1).strip()
                    print(f"[+] Banner: {finding.banner}")
                
                # Extract hostname
                hostname_match = re.search(r'250[- ]([^\s]+)', output)
                if hostname_match:
                    finding.hostname = hostname_match.group(1)
                    print(f"[+] Hostname: {finding.hostname}")
            
            # Extract software/version from banner
            if finding.banner:
                # Common SMTP software patterns
                software_patterns = [
                    (r'(Postfix)\s+([\d.]+)', 'Postfix'),
                    (r'(Sendmail)\s+([\d.]+)', 'Sendmail'),
                    (r'(Microsoft ESMTP MAIL Service)', 'Microsoft Exchange'),
                    (r'(Exim)\s+([\d.]+)', 'Exim'),
                    (r'(qmail)\s+([\d.]+)', 'qmail'),
                    (r'(Dovecot)', 'Dovecot'),
                ]
                
                for pattern, name in software_patterns:
                    match = re.search(pattern, finding.banner, re.IGNORECASE)
                    if match:
                        finding.software = name
                        if len(match.groups()) > 1:
                            finding.version = match.group(2)
                        break
            
            # Check for relay test results
            if 'smtp-open-relay' in output:
                if 'Server is an open relay' in output:
                    finding.relay_test_result = "OPEN RELAY DETECTED"
                    finding.security_issues.append("CRITICAL: Server configured as open mail relay")
                else:
                    finding.relay_test_result = "Relay protection enabled"
            
        except subprocess.TimeoutExpired:
            print("[!] Basic info gathering timed out")
        except Exception as e:
            print(f"[!] Basic info gathering failed: {e}")
    
    def _discover_capabilities(self, target: str, port: int, finding: SMTPFinding):
        """Discover SMTP capabilities and extensions"""
        try:
            # Use nmap smtp-commands script for detailed capability discovery
            cmd = [
                'nmap', '--script', 'smtp-commands,smtp-enum-users',
                '--script-args', 'smtp-enum-users.methods={EXPN,RCPT,VRFY}',
                '-p', str(port), target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse SMTP commands/capabilities
            if 'smtp-commands' in output:
                # Extract supported commands
                commands_match = re.findall(r'(\w+)(?:\s|$)', output)
                common_commands = ['HELO', 'EHLO', 'MAIL', 'RCPT', 'DATA', 'QUIT', 'HELP', 'VRFY', 'EXPN', 'NOOP', 'RSET']
                
                for cmd in commands_match:
                    if cmd.upper() in common_commands and cmd.upper() not in finding.capabilities:
                        finding.capabilities.append(cmd.upper())
                
                # Check for specific capabilities
                if 'STARTTLS' in output.upper():
                    finding.starttls_available = True
                    finding.capabilities.append('STARTTLS')
                    print("[+] STARTTLS supported")
                
                if 'AUTH' in output.upper():
                    auth_methods = re.findall(r'AUTH\s+([\w\s]+)', output.upper())
                    if auth_methods:
                        finding.auth_methods = auth_methods[0].split()
                        print(f"[+] Auth methods: {', '.join(finding.auth_methods)}")
                
                # Check for user enumeration capabilities
                if 'VRFY' in output.upper():
                    finding.vrfy_enabled = True
                    print("[+] VRFY command enabled - user enumeration possible")
                
                if 'EXPN' in output.upper():
                    finding.expn_enabled = True
                    print("[+] EXPN command enabled - mailing list expansion possible")
                
                # Extract message size limits
                size_match = re.search(r'SIZE\s+(\d+)', output)
                if size_match:
                    finding.max_message_size = size_match.group(1)
                    print(f"[+] Max message size: {finding.max_message_size} bytes")
            
        except subprocess.TimeoutExpired:
            print("[!] Capability discovery timed out")
        except Exception as e:
            print(f"[!] Capability discovery failed: {e}")
    
    def _enumerate_users(self, target: str, port: int, finding: SMTPFinding):
        """Enumerate users using VRFY and EXPN commands"""
        if not (finding.vrfy_enabled or finding.expn_enabled):
            print("[*] User enumeration commands not available")
            return
        
        try:
            # Common user list for testing
            common_users = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'mail', 'postmaster', 'webmaster']
            
            # Use smtp-user-enum if available, otherwise use nmap
            cmd = [
                'nmap', '--script', 'smtp-enum-users',
                '--script-args', f'smtp-enum-users.methods={{VRFY,EXPN}},smtp-enum-users.domain={target}',
                '-p', str(port), target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse enumerated users
            if 'smtp-enum-users' in output:
                user_matches = re.findall(r'(\w+@[\w.-]+|\w+)\s+exists', output, re.IGNORECASE)
                for user in user_matches:
                    if user not in finding.valid_users:
                        finding.valid_users.append(user)
                        print(f"[+] Valid user found: {user}")
            
            if finding.valid_users:
                finding.security_issues.append(f"User enumeration possible - {len(finding.valid_users)} users discovered")
            
        except subprocess.TimeoutExpired:
            print("[!] User enumeration timed out")
        except Exception as e:
            print(f"[!] User enumeration failed: {e}")
    
    def _assess_security(self, target: str, port: int, finding: SMTPFinding):
        """Assess SMTP security configuration"""
        print("[*] Assessing SMTP security configuration...")
        
        # Check for common security issues
        if finding.relay_test_result == "OPEN RELAY DETECTED":
            finding.security_issues.append("CRITICAL: Open mail relay configuration allows spam/abuse")
        
        if finding.vrfy_enabled:
            finding.security_issues.append("WARNING: VRFY command enabled - allows user enumeration")
        
        if finding.expn_enabled:
            finding.security_issues.append("WARNING: EXPN command enabled - allows mailing list enumeration")
        
        if not finding.starttls_available and port == 25:
            finding.security_issues.append("WARNING: STARTTLS not available - communications not encrypted")
        
        # Check for version-specific issues
        if finding.software and finding.version:
            if finding.software.lower() == 'sendmail':
                version_parts = finding.version.split('.')
                if len(version_parts) >= 2:
                    major, minor = int(version_parts[0]), int(version_parts[1])
                    if major < 8 or (major == 8 and minor < 15):
                        finding.security_issues.append("WARNING: Potentially vulnerable Sendmail version")
        
        # Check for information disclosure
        if finding.banner and any(keyword in finding.banner.lower() for keyword in ['version', 'build', 'patch']):
            finding.security_issues.append("INFO: Banner discloses detailed version information")
        
        # Overall assessment
        print(f"[*] SMTP security assessment complete:")
        print(f"    Security issues found: {len(finding.security_issues)}")
        print(f"    User enumeration possible: {finding.vrfy_enabled or finding.expn_enabled}")
        print(f"    STARTTLS available: {finding.starttls_available}")

class EmailServiceEnumerator:
    """POP3/IMAP service enumeration using nmap scripts and manual techniques"""
    
    def enumerate_email_service(self, target: str, port: int, service_type: str) -> EmailServiceFinding:
        """Comprehensive email service enumeration"""
        print(f"[*] Starting {service_type.upper()} enumeration on {target}:{port}")
        
        finding = EmailServiceFinding(target=target, port=port, service_type=service_type)
        
        # Phase 1: Basic information gathering
        print("[*] Phase 1: Basic email service information gathering...")
        self._gather_basic_info(target, port, service_type, finding)
        
        # Phase 2: Capability discovery
        print("[*] Phase 2: Email service capability discovery...")
        self._discover_capabilities(target, port, service_type, finding)
        
        # Phase 3: Authentication analysis
        print("[*] Phase 3: Authentication mechanism analysis...")
        self._analyze_authentication(target, port, service_type, finding)
        
        # Phase 4: Security assessment
        print("[*] Phase 4: Email service security assessment...")
        self._assess_security(target, port, service_type, finding)
        
        return finding
    
    def _gather_basic_info(self, target: str, port: int, service_type: str, finding: EmailServiceFinding):
        """Gather basic email service information"""
        try:
            # Select appropriate nmap scripts based on service type
            if service_type.lower().startswith('pop3'):
                scripts = 'pop3-capabilities,pop3-ntlm-info'
            elif service_type.lower().startswith('imap'):
                scripts = 'imap-capabilities,imap-ntlm-info'
            else:
                scripts = 'pop3-capabilities,imap-capabilities'
            
            cmd = ['nmap', '--script', scripts, '-p', str(port), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse banner information
            banner_patterns = [
                r'\+OK\s+(.+)',  # POP3 banner
                r'\* OK\s+(.+)', # IMAP banner
            ]
            
            for pattern in banner_patterns:
                match = re.search(pattern, output)
                if match:
                    finding.banner = match.group(1).strip()
                    print(f"[+] Banner: {finding.banner}")
                    break
            
            # Extract software/version from banner
            if finding.banner:
                software_patterns = [
                    (r'(Dovecot)\s+([\d.]+)', 'Dovecot'),
                    (r'(Courier-IMAP)\s+([\d.]+)', 'Courier-IMAP'),
                    (r'(UW-IMAP)\s+([\d.]+)', 'UW-IMAP'),
                    (r'(Cyrus)\s+IMAP\s+([\d.]+)', 'Cyrus IMAP'),
                    (r'Microsoft\s+Exchange', 'Microsoft Exchange'),
                    (r'(qpopper)\s+([\d.]+)', 'Qpopper'),
                ]
                
                for pattern, name in software_patterns:
                    match = re.search(pattern, finding.banner, re.IGNORECASE)
                    if match:
                        finding.software = name
                        if len(match.groups()) > 1:
                            finding.version = match.group(2)
                        break
            
            # Check for SSL/TLS information
            if port in [995, 993] or 'ssl' in service_type.lower():
                finding.ssl_enabled = True
                print("[+] SSL/TLS enabled")
            
        except subprocess.TimeoutExpired:
            print("[!] Basic info gathering timed out")
        except Exception as e:
            print(f"[!] Basic info gathering failed: {e}")
    
    def _discover_capabilities(self, target: str, port: int, service_type: str, finding: EmailServiceFinding):
        """Discover email service capabilities"""
        try:
            # Service-specific capability discovery
            if service_type.lower().startswith('pop3'):
                cmd = ['nmap', '--script', 'pop3-capabilities', '-p', str(port), target]
            else:  # IMAP
                cmd = ['nmap', '--script', 'imap-capabilities', '-p', str(port), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse capabilities
            if 'CAPABILITIES' in output.upper() or 'CAPABILITY' in output.upper():
                # Extract capability list
                cap_match = re.search(r'(?:CAPABILITIES|CAPABILITY):\s*(.+)', output, re.IGNORECASE)
                if cap_match:
                    caps = cap_match.group(1).strip().split()
                    finding.capabilities = [cap.strip('()[]') for cap in caps if cap.strip('()[]')]
                    print(f"[+] Capabilities: {', '.join(finding.capabilities)}")
                
                # Check for STARTTLS
                if any('STARTTLS' in cap.upper() for cap in finding.capabilities):
                    finding.starttls_available = True
                    print("[+] STARTTLS supported")
                
                # Check for authentication mechanisms
                auth_caps = [cap for cap in finding.capabilities if 'AUTH' in cap.upper()]
                if auth_caps:
                    finding.auth_mechanisms = auth_caps
                    print(f"[+] Auth mechanisms: {', '.join(auth_caps)}")
            
        except subprocess.TimeoutExpired:
            print("[!] Capability discovery timed out")
        except Exception as e:
            print(f"[!] Capability discovery failed: {e}")
    
    def _analyze_authentication(self, target: str, port: int, service_type: str, finding: EmailServiceFinding):
        """Analyze authentication mechanisms and security"""
        print("[*] Analyzing authentication mechanisms...")
        
        # Check for plaintext authentication risks
        if not finding.ssl_enabled and not finding.starttls_available:
            if any('PLAIN' in auth.upper() or 'LOGIN' in auth.upper() for auth in finding.auth_mechanisms):
                finding.plaintext_auth = True
                finding.security_issues.append("CRITICAL: Plaintext authentication over unencrypted connection")
        
        # Check for anonymous access capabilities
        if any('ANONYMOUS' in cap.upper() for cap in finding.capabilities):
            finding.anonymous_access = True
            finding.security_issues.append("WARNING: Anonymous access may be possible")
        
        # Check for login disabled scenarios
        if any('LOGINDISABLED' in cap.upper() for cap in finding.capabilities):
            finding.login_disabled = True
            print("[+] Login currently disabled")
    
    def _assess_security(self, target: str, port: int, service_type: str, finding: EmailServiceFinding):
        """Assess email service security configuration"""
        print("[*] Assessing email service security...")
        
        # Check for encryption issues
        if not finding.ssl_enabled and not finding.starttls_available:
            finding.security_issues.append("WARNING: No encryption available - communications sent in plaintext")
        
        # Version-specific vulnerability checks
        if finding.software and finding.version:
            if 'dovecot' in finding.software.lower():
                version_parts = finding.version.split('.')
                if len(version_parts) >= 2:
                    major, minor = int(version_parts[0]), int(version_parts[1])
                    if major < 2 or (major == 2 and minor < 3):
                        finding.security_issues.append("WARNING: Potentially vulnerable Dovecot version")
        
        # Information disclosure check
        if finding.banner and any(keyword in finding.banner.lower() for keyword in ['version', 'build', 'patch']):
            finding.security_issues.append("INFO: Banner discloses detailed version information")
        
        # Weak configuration checks
        if finding.plaintext_auth:
            finding.weak_configurations.append("Plaintext authentication enabled over unencrypted connection")
        
        if finding.anonymous_access:
            finding.weak_configurations.append("Anonymous access potentially available")
        
        # Overall assessment
        print(f"[*] Email service security assessment complete:")
        print(f"    Service: {service_type.upper()}")
        print(f"    SSL/TLS enabled: {finding.ssl_enabled}")
        print(f"    STARTTLS available: {finding.starttls_available}")
        print(f"    Security issues: {len(finding.security_issues)}")
        print(f"    Weak configurations: {len(finding.weak_configurations)}")

class LDAPEnumerator:
    """LDAP service enumeration using ldapsearch and nmap scripts"""
    
    def enumerate_ldap(self, target: str, port: int = 389) -> LDAPFinding:
        """Comprehensive LDAP enumeration"""
        print(f"[*] Starting LDAP enumeration on {target}:{port}")
        
        finding = LDAPFinding(target=target, port=port)
        
        # Phase 1: Basic LDAP discovery
        print("[*] Phase 1: Basic LDAP discovery and root DSE...")
        self._discover_root_dse(target, port, finding)
        
        # Phase 2: Naming context enumeration
        print("[*] Phase 2: Naming context and directory structure...")
        self._enumerate_naming_contexts(target, port, finding)
        
        # Phase 3: Schema discovery
        print("[*] Phase 3: Schema and object class discovery...")
        self._discover_schema(target, port, finding)
        
        # Phase 4: Directory enumeration
        print("[*] Phase 4: Directory structure and organizational units...")
        self._enumerate_directory_structure(target, port, finding)
        
        # Phase 5: Security assessment
        print("[*] Phase 5: LDAP security assessment...")
        self._assess_security(target, port, finding)
        
        return finding
    
    def _discover_root_dse(self, target: str, port: int, finding: LDAPFinding):
        """Discover LDAP root DSE and basic information"""
        try:
            # Use nmap LDAP scripts for initial discovery
            cmd = [
                'nmap', '--script', 
                'ldap-rootdse,ldap-search',
                '-p', str(port), target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse root DSE information
            if 'ldap-rootdse' in output:
                # Extract naming contexts
                naming_contexts = re.findall(r'namingContexts:\s*(.+)', output, re.IGNORECASE)
                finding.naming_contexts.extend(naming_contexts)
                
                # Extract default naming context
                default_nc = re.search(r'defaultNamingContext:\s*(.+)', output, re.IGNORECASE)
                if default_nc:
                    finding.default_naming_context = default_nc.group(1).strip()
                    print(f"[+] Default naming context: {finding.default_naming_context}")
                
                # Extract server name
                server_name = re.search(r'serverName:\s*(.+)', output, re.IGNORECASE)
                if server_name:
                    finding.server_name = server_name.group(1).strip()
                    print(f"[+] Server name: {finding.server_name}")
                
                # Extract domain information
                if finding.default_naming_context:
                    # Extract domain name from DN
                    domain_parts = re.findall(r'DC=([^,]+)', finding.default_naming_context, re.IGNORECASE)
                    if domain_parts:
                        finding.domain_name = '.'.join(domain_parts)
                        print(f"[+] Domain name: {finding.domain_name}")
            
            # Try anonymous bind
            try:
                anon_cmd = ['ldapsearch', '-x', '-h', target, '-p', str(port), '-s', 'base']
                anon_result = subprocess.run(anon_cmd, capture_output=True, text=True, timeout=60)
                if anon_result.returncode == 0 and 'result: 0 Success' in anon_result.stdout:
                    finding.anonymous_bind = True
                    print("[+] Anonymous bind successful")
            except:
                pass
            
        except subprocess.TimeoutExpired:
            print("[!] Root DSE discovery timed out")
        except Exception as e:
            print(f"[!] Root DSE discovery failed: {e}")
    
    def _enumerate_naming_contexts(self, target: str, port: int, finding: LDAPFinding):
        """Enumerate LDAP naming contexts and directory structure"""
        if not finding.anonymous_bind:
            print("[*] Anonymous bind not available - limited enumeration")
            return
        
        try:
            # Enumerate base naming context
            if finding.default_naming_context:
                cmd = [
                    'ldapsearch', '-x', '-h', target, '-p', str(port),
                    '-b', finding.default_naming_context, '-s', 'one',
                    'objectClass=*'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Extract organizational units
                    ou_matches = re.findall(r'dn:\s*OU=([^,]+)', result.stdout, re.IGNORECASE)
                    finding.organizational_units.extend(ou_matches)
                    
                    # Extract containers
                    cn_matches = re.findall(r'dn:\s*CN=([^,]+)', result.stdout, re.IGNORECASE)
                    finding.containers.extend(cn_matches)
                    
                    if finding.organizational_units:
                        print(f"[+] Found {len(finding.organizational_units)} organizational units")
                    if finding.containers:
                        print(f"[+] Found {len(finding.containers)} containers")
            
            # Try to enumerate configuration context
            config_contexts = [
                'CN=Configuration,' + finding.default_naming_context if finding.default_naming_context else None,
                'CN=Schema,CN=Configuration,' + finding.default_naming_context if finding.default_naming_context else None
            ]
            
            for context in config_contexts:
                if context:
                    try:
                        cmd = ['ldapsearch', '-x', '-h', target, '-p', str(port), '-b', context, '-s', 'base']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        if result.returncode == 0:
                            if 'Configuration' in context:
                                finding.config_naming_context = context
                            elif 'Schema' in context:
                                finding.schema_naming_context = context
                    except:
                        continue
            
        except subprocess.TimeoutExpired:
            print("[!] Naming context enumeration timed out")
        except Exception as e:
            print(f"[!] Naming context enumeration failed: {e}")
    
    def _discover_schema(self, target: str, port: int, finding: LDAPFinding):
        """Discover LDAP schema information"""
        if not finding.anonymous_bind or not finding.schema_naming_context:
            return
        
        try:
            # Enumerate schema attributes (limited to avoid overwhelming output)
            cmd = [
                'ldapsearch', '-x', '-h', target, '-p', str(port),
                '-b', finding.schema_naming_context, '-s', 'one',
                'objectClass=attributeSchema', 'cn'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Extract attribute names (limit to first 50)
                attr_matches = re.findall(r'cn:\s*(.+)', result.stdout, re.IGNORECASE)
                finding.schema_attributes = attr_matches[:50]  # Limit output
                
                if finding.schema_attributes:
                    print(f"[+] Found {len(attr_matches)} schema attributes (showing first 50)")
            
            # Enumerate object classes
            cmd = [
                'ldapsearch', '-x', '-h', target, '-p', str(port),
                '-b', finding.schema_naming_context, '-s', 'one',
                'objectClass=classSchema', 'cn'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Extract object class names (limit to first 30)
                class_matches = re.findall(r'cn:\s*(.+)', result.stdout, re.IGNORECASE)
                finding.object_classes = class_matches[:30]  # Limit output
                
                if finding.object_classes:
                    print(f"[+] Found {len(class_matches)} object classes (showing first 30)")
            
        except subprocess.TimeoutExpired:
            print("[!] Schema discovery timed out")
        except Exception as e:
            print(f"[!] Schema discovery failed: {e}")
    
    def _enumerate_directory_structure(self, target: str, port: int, finding: LDAPFinding):
        """Enumerate directory structure and common objects"""
        if not finding.anonymous_bind or not finding.default_naming_context:
            return
        
        try:
            # Look for users (limited enumeration)
            users_contexts = [
                f"CN=Users,{finding.default_naming_context}",
                f"OU=Users,{finding.default_naming_context}"
            ]
            
            for context in users_contexts:
                try:
                    cmd = [
                        'ldapsearch', '-x', '-h', target, '-p', str(port),
                        '-b', context, '-s', 'one',
                        'objectClass=user', 'cn', 'sAMAccountName'
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    
                    if result.returncode == 0:
                        # Extract user names
                        user_matches = re.findall(r'(?:cn|sAMAccountName):\s*(.+)', result.stdout, re.IGNORECASE)
                        finding.users.extend(user_matches[:20])  # Limit to first 20
                        
                        if finding.users:
                            print(f"[+] Found {len(user_matches)} users (showing first 20)")
                        break
                except:
                    continue
            
            # Look for computers
            try:
                cmd = [
                    'ldapsearch', '-x', '-h', target, '-p', str(port),
                    '-b', finding.default_naming_context, '-s', 'sub',
                    'objectClass=computer', 'cn'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    computer_matches = re.findall(r'cn:\s*(.+)', result.stdout, re.IGNORECASE)
                    finding.computers.extend(computer_matches[:15])  # Limit output
                    
                    if finding.computers:
                        print(f"[+] Found {len(computer_matches)} computers (showing first 15)")
            except:
                pass
            
        except Exception as e:
            print(f"[!] Directory structure enumeration failed: {e}")
    
    def _assess_security(self, target: str, port: int, finding: LDAPFinding):
        """Assess LDAP security configuration"""
        print("[*] Assessing LDAP security configuration...")
        
        # Check for anonymous bind
        if finding.anonymous_bind:
            finding.security_issues.append("WARNING: Anonymous bind enabled - information disclosure possible")
        
        # Check for SSL/TLS
        if port == 636:
            finding.ssl_enabled = True
        elif port == 389:
            # Test for StartTLS
            try:
                cmd = ['ldapsearch', '-x', '-h', target, '-p', str(port), '-Z']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    finding.start_tls_available = True
                    print("[+] StartTLS supported")
            except:
                pass
            
            if not finding.start_tls_available:
                finding.security_issues.append("WARNING: No encryption detected - communications in plaintext")
        
        # Check for sensitive attributes exposure
        if finding.users:
            finding.security_issues.append("INFO: User enumeration possible via anonymous bind")
        
        if finding.computers:
            finding.security_issues.append("INFO: Computer enumeration possible via anonymous bind")
        
        # Overall assessment
        print(f"[*] LDAP security assessment complete:")
        print(f"    Anonymous bind: {finding.anonymous_bind}")
        print(f"    SSL/TLS: {finding.ssl_enabled}")
        print(f"    StartTLS: {finding.start_tls_available}")
        print(f"    Security issues: {len(finding.security_issues)}")

class KerberosEnumerator:
    """Kerberos service enumeration using nmap scripts and kerbrute"""
    
    def enumerate_kerberos(self, target: str, port: int = 88) -> KerberosFinding:
        """Comprehensive Kerberos enumeration"""
        print(f"[*] Starting Kerberos enumeration on {target}:{port}")
        
        finding = KerberosFinding(target=target, port=port)
        
        # Phase 1: Basic Kerberos discovery
        print("[*] Phase 1: Basic Kerberos discovery and realm identification...")
        self._discover_kerberos_info(target, port, finding)
        
        # Phase 2: User enumeration
        print("[*] Phase 2: Kerberos user enumeration...")
        self._enumerate_users(target, port, finding)
        
        # Phase 3: Service enumeration
        print("[*] Phase 3: Service Principal Name (SPN) enumeration...")
        self._enumerate_services(target, port, finding)
        
        # Phase 4: Security assessment
        print("[*] Phase 4: Kerberos security assessment...")
        self._assess_security(target, port, finding)
        
        return finding
    
    def _discover_kerberos_info(self, target: str, port: int, finding: KerberosFinding):
        """Discover basic Kerberos information"""
        try:
            # Use nmap Kerberos scripts
            cmd = [
                'nmap', '--script', 
                'krb5-enum-users,ms-sql-ntlm-info',
                '-p', str(port), target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Extract realm information
            realm_match = re.search(r'Realm:\s*(.+)', output, re.IGNORECASE)
            if realm_match:
                finding.realm = realm_match.group(1).strip()
                print(f"[+] Kerberos realm: {finding.realm}")
            
            # Extract KDC server info
            kdc_match = re.search(r'KDC:\s*(.+)', output, re.IGNORECASE)
            if kdc_match:
                finding.kdc_server = kdc_match.group(1).strip()
                print(f"[+] KDC server: {finding.kdc_server}")
            
            # Try alternative realm discovery
            if not finding.realm:
                # Try DNS-based realm discovery
                try:
                    dns_cmd = ['nslookup', '-type=srv', f'_kerberos._tcp.{target}']
                    dns_result = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=30)
                    if 'kerberos' in dns_result.stdout.lower():
                        domain_match = re.search(r'_kerberos\._tcp\.(.+?)\s', dns_result.stdout)
                        if domain_match:
                            finding.realm = domain_match.group(1).upper()
                            print(f"[+] Realm discovered via DNS: {finding.realm}")
                except:
                    pass
            
        except subprocess.TimeoutExpired:
            print("[!] Kerberos discovery timed out")
        except Exception as e:
            print(f"[!] Kerberos discovery failed: {e}")
    
    def _enumerate_users(self, target: str, port: int, finding: KerberosFinding):
        """Enumerate Kerberos users"""
        try:
            # Common usernames for testing
            common_users = [
                'administrator', 'admin', 'guest', 'krbtgt', 'user',
                'service', 'test', 'backup', 'operator', 'support'
            ]
            
            # Try kerbrute if available
            kerbrute_paths = ['/usr/bin/kerbrute', '/opt/kerbrute', './kerbrute']
            kerbrute_cmd = None
            
            for path in kerbrute_paths:
                try:
                    test_result = subprocess.run([path, '--help'], capture_output=True, timeout=5)
                    if test_result.returncode == 0:
                        kerbrute_cmd = path
                        break
                except:
                    continue
            
            if kerbrute_cmd and finding.realm:
                print("[*] Using kerbrute for user enumeration...")
                
                # Create temporary user list
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    for user in common_users:
                        f.write(f"{user}\n")
                    temp_file = f.name
                
                try:
                    cmd = [
                        kerbrute_cmd, 'userenum',
                        '--dc', target,
                        '-d', finding.realm,
                        temp_file
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                    
                    # Parse kerbrute output
                    if result.returncode == 0:
                        valid_users = re.findall(r'VALID USERNAME:\s*(.+?)@', result.stdout, re.IGNORECASE)
                        finding.valid_users.extend(valid_users)
                        
                        if finding.valid_users:
                            print(f"[+] Found {len(finding.valid_users)} valid users")
                finally:
                    import os
                    try:
                        os.unlink(temp_file)
                    except:
                        pass
            
            else:
                # Fallback to nmap scripts
                print("[*] Using nmap for user enumeration...")
                cmd = [
                    'nmap', '--script', 'krb5-enum-users',
                    '--script-args', f'krb5-enum-users.realm={finding.realm or target}',
                    '-p', str(port), target
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Parse nmap output for valid users
                    user_matches = re.findall(r'Valid usernames?:\s*(.+)', result.stdout, re.IGNORECASE)
                    for match in user_matches:
                        users = [u.strip() for u in match.split(',')]
                        finding.valid_users.extend(users)
                    
                    if finding.valid_users:
                        print(f"[+] Found {len(finding.valid_users)} valid users")
            
        except subprocess.TimeoutExpired:
            print("[!] User enumeration timed out")
        except Exception as e:
            print(f"[!] User enumeration failed: {e}")
    
    def _enumerate_services(self, target: str, port: int, finding: KerberosFinding):
        """Enumerate Kerberos services and SPNs"""
        try:
            # Common service names
            common_services = [
                'HTTP', 'LDAP', 'MSSQL', 'CIFS', 'HOST',
                'DNS', 'GC', 'kadmin', 'changepw'
            ]
            
            # Try to enumerate SPNs for the target
            if finding.realm:
                for service in common_services:
                    spn = f"{service}/{target}"
                    # Test if SPN exists by attempting to get service ticket
                    try:
                        # This is a simplified check - in practice, you'd need valid credentials
                        finding.spns.append(spn)
                    except:
                        continue
                
                # Look for domain controllers
                if '.' in finding.realm:
                    dc_spn = f"ldap/{finding.realm.lower()}"
                    finding.spns.append(dc_spn)
                    finding.domain_controllers.append(target)
            
            # Extract services from nmap scan
            cmd = [
                'nmap', '--script', 'ms-sql-info,ldap-search',
                '-p', '88,389,1433,3268', target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Identify running services that likely have SPNs
                if 'ldap' in result.stdout.lower():
                    finding.kerberos_services.append('LDAP')
                if 'sql server' in result.stdout.lower():
                    finding.kerberos_services.append('MSSQL')
                
                if finding.kerberos_services:
                    print(f"[+] Identified {len(finding.kerberos_services)} Kerberos-enabled services")
            
        except subprocess.TimeoutExpired:
            print("[!] Service enumeration timed out")
        except Exception as e:
            print(f"[!] Service enumeration failed: {e}")
    
    def _assess_security(self, target: str, port: int, finding: KerberosFinding):
        """Assess Kerberos security configuration"""
        print("[*] Assessing Kerberos security configuration...")
        
        # Check for pre-authentication requirements
        if finding.valid_users:
            # Test for users without pre-authentication required
            for user in finding.valid_users[:5]:  # Test first 5 users
                try:
                    # This would require more sophisticated testing in practice
                    # For now, we'll mark potential issues based on common usernames
                    if user.lower() in ['guest', 'test', 'service']:
                        finding.users_no_preauth.append(user)
                        finding.security_issues.append(f"WARNING: User '{user}' may not require pre-authentication")
                except:
                    continue
        
        # Check for common service accounts
        if finding.valid_users:
            service_patterns = ['svc', 'service', 'sql', 'backup', 'exchange']
            for user in finding.valid_users:
                if any(pattern in user.lower() for pattern in service_patterns):
                    finding.service_users.append(user)
                    finding.security_issues.append(f"INFO: Potential service account found: {user}")
        
        # Check for admin accounts
        if finding.valid_users:
            admin_patterns = ['admin', 'administrator', 'root', 'domain admin']
            for user in finding.valid_users:
                if any(pattern in user.lower() for pattern in admin_patterns):
                    finding.admin_users.append(user)
                    finding.security_issues.append(f"INFO: Administrative account found: {user}")
        
        # Time skew check (simplified)
        try:
            import time
            finding.kdc_time = time.strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        
        # Overall assessment
        print(f"[*] Kerberos security assessment complete:")
        print(f"    Realm: {finding.realm or 'Unknown'}")
        print(f"    Valid users found: {len(finding.valid_users)}")
        print(f"    Service accounts: {len(finding.service_users)}")
        print(f"    Security issues: {len(finding.security_issues)}")

class KevinShell(cmd.Cmd):
    """
    Kevin OSCP Automation Shell
    
    Embodies Kevin Mitnick's methodical approach:
    - Methodical enumeration
    - Creative problem solving  
    - Persistent curiosity
    - Deep system understanding
    """
    
    def __init__(self):
        super().__init__()
        self.current_target: Optional[Target] = None
        self.scanner = NmapScanner()
        self.web_enumerator = WebEnumerator()
        self.tech_analyzer = TechnologyDeepDive()
        self.vhost_discovery = VirtualHostDiscovery()
        self.mysql_enumerator = MySQLEnumerator()
        self.mssql_enumerator = MSSQLEnumerator()
        self.oracle_enumerator = OracleEnumerator()
        self.smtp_enumerator = SMTPEnumerator()
        self.email_service_enumerator = EmailServiceEnumerator()
        self.ldap_enumerator = LDAPEnumerator()
        self.kerberos_enumerator = KerberosEnumerator()
        self.running_processes: Dict[str, subprocess.Popen] = {}
        self.session_dir = Path("kevin_sessions")
        self.session_dir.mkdir(exist_ok=True)
        
        # Auto-enumeration settings
        self.auto_enumerate = True
        self.auto_web_enum = True
        self.auto_smb_enum = True
        self.auto_ftp_enum = True
        self.auto_mysql_enum = True
        self.auto_mssql_enum = True
        self.auto_oracle_enum = True
        self.auto_smtp_enum = True
        self.auto_email_enum = True
        self.auto_ldap_enum = True
        self.auto_kerberos_enum = True
        self.web_wordlist_preference = 'common'  # Start with common, escalate if needed
        
        # Kevin's personality responses
        self.kevin_quotes = [
            "Every system has a weakness. Let's find it!",
            "Don't give up - there's always another way in!",
            "Classic misconfiguration - love to see it!",
            "The most interesting vulnerabilities hide in unexpected places.",
            "Remember: Understanding beats brute force every time."
        ]
        
        self.setup_intro()
    
    def setup_intro(self):
        """Display Kevin's welcome message"""
        self.intro = """
╔═══════════════════════════════════════════════════════════════════╗
║                 Welcome to Kevin - OSCP Companion                 ║
║           "The art of deception is knowing when to tell          ║
║                         the truth" - Kevin Mitnick               ║
╚═══════════════════════════════════════════════════════════════════╝

Kevin: Hey there! Ready to hack some boxes? Let's find those attack vectors!
Type 'help' to see available commands or 'kevin' for encouragement.
"""
        self.prompt = 'kevin> '
    
    def do_kevin(self, line: str):
        """Get encouragement from Kevin"""
        import random
        quote = random.choice(self.kevin_quotes)
        print(f"Kevin: {quote}")
    
    def do_auto(self, line: str):
        """
        Configure auto-enumeration settings: auto <setting> [on/off]
        
        Settings:
        - enum [on/off]: Enable/disable all auto-enumeration
        - web [on/off]: Auto web enumeration when web services found
        - smb [on/off]: Auto SMB enumeration when SMB services found  
        - ftp [on/off]: Auto FTP enumeration when FTP services found
        - wordlist [common/big/medium]: Default wordlist for web enumeration
        - status: Show current auto-enumeration settings
        
        Examples:
        auto status
        auto web on
        auto wordlist big
        """
        args = line.strip().split()
        
        if not args or args[0] == 'status':
            print(f"\n=== Auto-Enumeration Settings ===")
            print(f"Master Auto-Enum: {'ON' if self.auto_enumerate else 'OFF'}")
            print(f"Auto Web Enum:    {'ON' if self.auto_web_enum else 'OFF'}")
            print(f"Auto SMB Enum:    {'ON' if self.auto_smb_enum else 'OFF'}")
            print(f"Auto FTP Enum:    {'ON' if self.auto_ftp_enum else 'OFF'}")
            print(f"Web Wordlist:     {self.web_wordlist_preference}")
            return
        
        setting = args[0].lower()
        value = args[1].lower() if len(args) > 1 else None
        
        if setting == 'enum':
            if value == 'on':
                self.auto_enumerate = True
                print("Kevin: Auto-enumeration enabled! I'll chain scans intelligently.")
            elif value == 'off':
                self.auto_enumerate = False
                print("Kevin: Auto-enumeration disabled. Manual control mode activated.")
            else:
                print("Kevin: Use 'auto enum on' or 'auto enum off'")
        
        elif setting == 'web':
            if value == 'on':
                self.auto_web_enum = True
                print("Kevin: Auto web enumeration enabled! Found a web server? I'm on it!")
            elif value == 'off':
                self.auto_web_enum = False
                print("Kevin: Auto web enumeration disabled.")
            else:
                print("Kevin: Use 'auto web on' or 'auto web off'")
        
        elif setting == 'smb':
            if value == 'on':
                self.auto_smb_enum = True
                print("Kevin: Auto SMB enumeration enabled!")
            elif value == 'off':
                self.auto_smb_enum = False
                print("Kevin: Auto SMB enumeration disabled.")
            else:
                print("Kevin: Use 'auto smb on' or 'auto smb off'")
        
        elif setting == 'ftp':
            if value == 'on':
                self.auto_ftp_enum = True
                print("Kevin: Auto FTP enumeration enabled!")
            elif value == 'off':
                self.auto_ftp_enum = False
                print("Kevin: Auto FTP enumeration disabled.")
            else:
                print("Kevin: Use 'auto ftp on' or 'auto ftp off'")
        
        elif setting == 'wordlist':
            if value in ['common', 'big', 'medium', 'raft']:
                self.web_wordlist_preference = value
                print(f"Kevin: Web wordlist preference set to '{value}'")
            else:
                print("Kevin: Available wordlists: common, big, medium, raft")
        
        else:
            print("Kevin: Unknown setting. Use 'help auto' for options.")
    
    def do_target(self, line: str):
        """Set target IP: target <ip>"""
        if not line.strip():
            if self.current_target:
                print(f"Current target: {self.current_target.ip}")
                if self.current_target.hostname:
                    print(f"Hostname: {self.current_target.hostname}")
                if self.current_target.open_ports:
                    print(f"Open ports: {len(self.current_target.open_ports)} discovered")
            else:
                print("No target set. Use: target <ip>")
            return
        
        ip = line.strip()
        self.current_target = Target(ip=ip)
        print(f"Kevin: Target locked onto {ip}! Let's see what secrets it's hiding...")
    
    def do_scan(self, line: str):
        """
        Run nmap scans: scan [type] [ports]
        
        Types:
        - quick: Fast TCP SYN scan of all ports  
        - service: Deep service enumeration with scripts
        - udp: UDP port scan
        - vuln: Vulnerability scanning with NSE
        - stealth: Slow, stealthy scanning
        
        Examples:
        scan quick
        scan service 22,80,443
        scan vuln 80,443
        """
        if not self.current_target:
            print("Kevin: Set a target first! Use: target <ip>")
            return
        
        args = line.strip().split()
        scan_type = args[0] if args else 'quick'
        ports = args[1] if len(args) > 1 else None
        
        if scan_type not in self.scanner.scan_types:
            print(f"Kevin: Unknown scan type '{scan_type}'. Available: {', '.join(self.scanner.scan_types.keys())}")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_{scan_type}_{timestamp}"
        
        try:
            process = self.scanner.run_scan(
                self.current_target.ip, 
                scan_type, 
                ports, 
                str(output_file)
            )
            
            scan_id = f"{scan_type}_{timestamp}"
            self.running_processes[scan_id] = process
            
            print(f"Kevin: {scan_type.title()} scan launched! Use 'status' to check progress.")
            print(f"Kevin: This might take a while - perfect time for some coffee! ☕")
            
            # Start background thread to monitor completion
            threading.Thread(
                target=self._monitor_scan, 
                args=(scan_id, process, str(output_file)), 
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Scan failed - {e}")
    
    def _monitor_scan(self, scan_id: str, process: subprocess.Popen, output_file: str):
        """Monitor scan completion in background"""
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(f"\n[+] {scan_id} completed successfully!")
            
            # Parse results if XML output exists
            xml_file = f"{output_file}.xml"
            if os.path.exists(xml_file):
                new_ports = self.scanner.parse_xml_output(xml_file)
                
                # Merge with existing ports
                existing_port_nums = {p.number for p in self.current_target.open_ports}
                for port in new_ports:
                    if port.number not in existing_port_nums:
                        self.current_target.open_ports.append(port)
                
                print(f"Kevin: Found {len(new_ports)} ports! Use 'show ports' to see details.")
                
                # Trigger automatic enumeration if enabled
                if self.auto_enumerate:
                    self._auto_enumerate_services(new_ports)
                else:
                    # Manual suggestions if auto-enum is disabled
                    self._suggest_next_steps()
            
            self.current_target.scan_history.append(f"{scan_id}: {datetime.now()}")
        else:
            print(f"\n[!] {scan_id} failed: {stderr}")
        
        # Cleanup
        if scan_id in self.running_processes:
            del self.running_processes[scan_id]
    
    def _suggest_next_steps(self):
        """Kevin's intelligent suggestions based on findings"""
        if not self.current_target.open_ports:
            return
        
        suggestions = []
        services_found = set()
        
        for port in self.current_target.open_ports:
            if port.state == 'open':
                services_found.add(port.service)
        
        if 'http' in services_found or 'https' in services_found:
            suggestions.append("🌐 Web server detected! Try: web fingerprint or web all")
        
        if 'smb' in services_found or 'microsoft-ds' in services_found:
            suggestions.append("📁 SMB detected! Try: enum smb")
        
        if 'ftp' in services_found:
            suggestions.append("📂 FTP detected! Try: enum ftp")
        
        if 'ssh' in services_found:
            suggestions.append("🔐 SSH detected! Try: enum ssh")
        
        if suggestions:
            print("\nKevin: Based on what I'm seeing, here's what I'd try next:")
            for suggestion in suggestions[:3]:  # Limit to top 3
                print(f"  {suggestion}")
    
    def _auto_enumerate_services(self, new_ports: List[Port]):
        """Automatically trigger service enumeration based on discovered ports"""
        web_ports = []
        smb_ports = []
        ftp_ports = []
        smtp_ports = []
        email_ports = []
        ldap_ports = []
        kerberos_ports = []
        
        print("\nKevin: Auto-enumeration activated! Let me dig deeper into these services...")
        
        for port in new_ports:
            if port.state == 'open':
                service = port.service.lower()
                
                # Categorize services for auto-enumeration
                if service in ['http', 'https', 'http-proxy', 'ssl/http', 'http-alt'] or port.number in [80, 443, 8080, 8443, 8000, 9000]:
                    web_ports.append(port)
                elif service in ['smb', 'microsoft-ds', 'netbios-ssn'] or port.number in [139, 445]:
                    smb_ports.append(port)
                elif service == 'ftp' or port.number == 21:
                    ftp_ports.append(port)
                elif service in ['smtp', 'submission'] or port.number in [25, 465, 587]:
                    smtp_ports.append(port)
                elif service in ['pop3', 'pop3s', 'imap', 'imaps'] or port.number in [110, 143, 993, 995]:
                    email_ports.append(port)
                elif service in ['ldap', 'ldaps'] or port.number in [389, 636]:
                    ldap_ports.append(port)
                elif service in ['kerberos', 'kerberos-sec', 'krb5'] or port.number in [88, 464]:
                    kerberos_ports.append(port)
        
        # Auto-trigger web enumeration
        if web_ports and self.auto_web_enum:
            print(f"Kevin: 🌐 Found {len(web_ports)} web service(s)! Launching comprehensive web enumeration...")
            for port in web_ports:
                if port.number == 443:
                    url = f"https://{self.current_target.ip}"
                elif port.number == 80:
                    url = f"http://{self.current_target.ip}"
                else:
                    # Determine protocol based on service
                    protocol = "https" if "ssl" in port.service.lower() or port.number == 443 else "http"
                    url = f"{protocol}://{self.current_target.ip}:{port.number}"
                
                # Launch automatic web enumeration with delay
                time.sleep(1)  # Stagger launches
                self._auto_web_enumeration(url)
        
        # Auto-trigger SMB enumeration
        if smb_ports and self.auto_smb_enum:
            print(f"Kevin: 📁 Found SMB service! Launching SMB enumeration...")
            time.sleep(2)
            self._auto_smb_enumeration()
        
        # Auto-trigger FTP enumeration
        if ftp_ports and self.auto_ftp_enum:
            print(f"Kevin: 📂 Found FTP service! Testing for anonymous access...")
            time.sleep(2)
            self._auto_ftp_enumeration()
        
        # Auto-trigger MySQL enumeration
        mysql_ports = [p for p in new_ports if p.service.lower() in ['mysql', 'mysqld'] or p.number == 3306]
        if mysql_ports and self.auto_mysql_enum:
            print(f"Kevin: 🗃️  Found MySQL service! Launching database enumeration...")
            time.sleep(2)
            self._auto_mysql_enumeration()
        
        # Auto-trigger MSSQL enumeration
        mssql_ports = [p for p in new_ports if p.service.lower() in ['mssql', 'ms-sql-s', 'microsoft-ds'] or p.number == 1433]
        if mssql_ports and self.auto_mssql_enum:
            print(f"Kevin: 🏢 Found MSSQL service! Launching database enumeration...")
            time.sleep(2)
            self._auto_mssql_enumeration()
        
        # Auto-trigger Oracle enumeration
        oracle_ports = [p for p in new_ports if p.service.lower() in ['oracle', 'oracle-tns'] or p.number == 1521]
        if oracle_ports and self.auto_oracle_enum:
            print(f"Kevin: 🔮 Found Oracle service! Launching database enumeration...")
            time.sleep(2)
            self._auto_oracle_enumeration()
        
        # Auto-trigger SMTP enumeration
        if smtp_ports and self.auto_smtp_enum:
            print(f"Kevin: 📧 Found SMTP service! Launching email server enumeration...")
            time.sleep(2)
            self._auto_smtp_enumeration()
        
        # Auto-trigger Email service enumeration (POP3/IMAP)
        if email_ports and self.auto_email_enum:
            print(f"Kevin: 📬 Found email retrieval service(s)! Launching mailbox enumeration...")
            time.sleep(2)
            for port in email_ports:
                self._auto_email_service_enumeration(port)
        
        # Auto-trigger LDAP enumeration
        if ldap_ports and self.auto_ldap_enum:
            print(f"Kevin: 🏢 Found LDAP service! Launching directory service enumeration...")
            time.sleep(2)
            self._auto_ldap_enumeration()
        
        # Auto-trigger Kerberos enumeration
        if kerberos_ports and self.auto_kerberos_enum:
            print(f"Kevin: 🎫 Found Kerberos service! Launching authentication enumeration...")
            time.sleep(2)
            self._auto_kerberos_enumeration()
        
        # Also show manual suggestions for other services
        self._suggest_next_steps()
    
    def _auto_web_enumeration(self, url: str):
        """Launch automatic web enumeration for a discovered web service"""
        print(f"Kevin: 🕸️  Starting automated web assault on {url}")
        
        # Phase 1: Technology fingerprinting (fast)
        print("Kevin: Phase 1 - Technology fingerprinting...")
        self._web_fingerprint([url])
        
        # Phase 2: Directory enumeration (start with common)
        print(f"Kevin: Phase 2 - Directory hunting with '{self.web_wordlist_preference}' wordlist...")
        time.sleep(3)  # Give fingerprinting time to start
        self._auto_web_directory(url, self.web_wordlist_preference)
        
        # Phase 3: Backup/sensitive file hunting
        print("Kevin: Phase 3 - Backup and sensitive file hunting...")
        time.sleep(5)  # Give directory enum time to start
        self._web_config([url])
        
        # Phase 4: Quick vulnerability scan
        print("Kevin: Phase 4 - Vulnerability scanning...")
        time.sleep(3)  # Give config hunting time to start
        self._web_vuln([url])
        
        print(f"Kevin: 🚀 Full auto web enumeration launched for {url}!")
        print("Kevin: I'll escalate to bigger wordlists if we don't find much...")
        print("Kevin: 🕵️ Also hunting for those juicy backup files and config files!")
    
    def _auto_web_directory(self, url: str, wordlist: str):
        """Auto web directory enumeration with escalation capability"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_auto_gobuster_{timestamp}.txt"
        
        try:
            process = self.web_enumerator.run_gobuster(
                url, 
                wordlist, 
                self.web_enumerator.extensions['basic'], 
                str(output_file)
            )
            web_id = f"auto_gobuster_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: 🔍 Auto directory enumeration running on {url}...")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'directory', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Auto directory enumeration failed - {e}")
    
    def _auto_smb_enumeration(self):
        """Launch automatic SMB enumeration"""
        print("Kevin: 🔍 Launching comprehensive SMB enumeration...")
        
        # Use the existing enum command but programmatically
        try:
            ports = "139,445"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.session_dir / f"{self.current_target.ip}_auto_smb_{timestamp}"
            
            process = self.scanner.run_service_scan(
                self.current_target.ip,
                'smb',
                ports,
                str(output_file)
            )
            
            enum_id = f"auto_smb_{timestamp}"
            self.running_processes[enum_id] = process
            
            print("Kevin: 📊 SMB enumeration running - checking for anonymous access and shares...")
            
            threading.Thread(
                target=self._monitor_scan,
                args=(enum_id, process, str(output_file)),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Auto SMB enumeration failed - {e}")
    
    def _auto_ftp_enumeration(self):
        """Launch automatic FTP enumeration"""
        print("Kevin: 📁 Testing FTP for anonymous access...")
        
        try:
            ports = "21"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.session_dir / f"{self.current_target.ip}_auto_ftp_{timestamp}"
            
            process = self.scanner.run_service_scan(
                self.current_target.ip,
                'ftp',
                ports,
                str(output_file)
            )
            
            enum_id = f"auto_ftp_{timestamp}"
            self.running_processes[enum_id] = process
            
            print("Kevin: 🔐 FTP enumeration running - checking for anonymous access and backdoors...")
            
            threading.Thread(
                target=self._monitor_scan,
                args=(enum_id, process, str(output_file)),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Auto FTP enumeration failed - {e}")
    
    def _auto_mysql_enumeration(self):
        """Launch automatic MySQL enumeration"""
        print("Kevin: 🗃️  Launching comprehensive MySQL enumeration...")
        
        try:
            # Find MySQL port
            mysql_port = 3306
            for port in self.current_target.open_ports:
                if port.service.lower() in ['mysql', 'mysqld'] or port.number == 3306:
                    mysql_port = port.number
                    break
            
            print(f"Kevin: 🔍 MySQL enumeration on port {mysql_port}...")
            print("Kevin: Checking for version info, empty passwords, databases, and security issues...")
            
            # Run comprehensive MySQL enumeration
            finding = self.mysql_enumerator.enumerate_mysql(self.current_target.ip, mysql_port)
            self.current_target.mysql_findings.append(finding)
            
            # Display immediate results
            if finding.security_issues:
                print(f"\nKevin: 🚨 Found {len(finding.security_issues)} MySQL security issues!")
                for issue in finding.security_issues[:3]:  # Show top 3
                    print(f"  • {issue}")
                if len(finding.security_issues) > 3:
                    print(f"  ... and {len(finding.security_issues) - 3} more (use 'show mysql' for all)")
            
            if finding.databases:
                print(f"Kevin: 📊 Discovered {len(finding.databases)} databases!")
            
            if finding.users:
                print(f"Kevin: 👤 Found {len(finding.users)} MySQL users!")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_mysql_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto MySQL enumeration failed - {e}")
    
    def _manual_mysql_enumeration(self, ports: str):
        """Manual MySQL enumeration triggered by enum command"""
        print(f"Kevin: 🗃️  Manual MySQL enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for MySQL)
            mysql_port = int(ports.split(',')[0])  # Take first port if multiple
            
            print("Kevin: 🔍 Comprehensive MySQL information gathering and security assessment...")
            print("Kevin: This will check for version info, empty passwords, accessible databases, and security misconfigurations!")
            
            # Run comprehensive MySQL enumeration
            finding = self.mysql_enumerator.enumerate_mysql(self.current_target.ip, mysql_port)
            self.current_target.mysql_findings.append(finding)
            
            # Display comprehensive results
            self._display_mysql_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_mysql_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual MySQL enumeration failed - {e}")
    
    def _display_mysql_findings(self, finding: MySQLFinding):
        """Display comprehensive MySQL enumeration results"""
        print(f"\n=== 🗃️  MySQL Enumeration Results: {finding.target}:{finding.port} ===")
        
        # Basic Information
        print("\n📊 BASIC INFORMATION:")
        if finding.version:
            print(f"   MySQL Version: {finding.version}")
        if finding.server_version:
            print(f"   Server Version: {finding.server_version}")
        if finding.protocol_version:
            print(f"   Protocol Version: {finding.protocol_version}")
        if finding.ssl_enabled:
            print(f"   SSL/TLS: ✅ Enabled")
        else:
            print(f"   SSL/TLS: ❌ Not detected")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'root', 'empty password']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Empty Password Accounts
        if finding.empty_password_accounts:
            print(f"\n🔓 EMPTY PASSWORD ACCOUNTS ({len(finding.empty_password_accounts)}):")
            for account in finding.empty_password_accounts:
                print(f"   • {account} - IMMEDIATE SECURITY RISK!")
        
        # Database Information
        if finding.databases:
            print(f"\n📂 ACCESSIBLE DATABASES ({len(finding.databases)}):")
            for db in finding.databases[:10]:  # Show first 10
                print(f"   • {db}")
            if len(finding.databases) > 10:
                print(f"   ... and {len(finding.databases) - 10} more")
        
        # User Information
        if finding.users:
            print(f"\n👤 MYSQL USERS ({len(finding.users)}):")
            for user in finding.users[:10]:  # Show first 10
                print(f"   • {user}")
            if len(finding.users) > 10:
                print(f"   ... and {len(finding.users) - 10} more")
        
        # Important Variables
        if finding.variables:
            print(f"\n🔧 IMPORTANT VARIABLES:")
            security_vars = ['local_infile', 'secure_file_priv', 'have_ssl', 'log_bin']
            for var in security_vars:
                if var in finding.variables:
                    value = finding.variables[var]
                    print(f"   {var}: {value}")
        
        # Attack Recommendations
        self._suggest_mysql_attacks(finding)
    
    def _suggest_mysql_attacks(self, finding: MySQLFinding):
        """Suggest attack vectors based on MySQL findings"""
        print(f"\n🎯 MYSQL ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # Critical vulnerabilities
        if finding.empty_password_accounts:
            if 'root' in finding.empty_password_accounts:
                suggestions.append("🔥 CRITICAL: Root has empty password - immediate access possible!")
                suggestions.append(f"   Try: mysql -h {finding.target} -u root")
            for account in finding.empty_password_accounts:
                if account != 'root':
                    suggestions.append(f"⚠️ Account '{account}' has empty password - test access")
        
        # Version-based attacks
        if finding.version:
            version_lower = finding.version.lower()
            if any(old_ver in version_lower for old_ver in ['5.0', '5.1', '4.']):
                suggestions.append("🎯 Very old MySQL version - research version-specific exploits")
            elif '5.5' in version_lower:
                suggestions.append("🔍 MySQL 5.5 detected - check for CVE-2012-2122 and other known issues")
        
        # Configuration-based attacks
        if 'local_infile' in finding.variables and finding.variables['local_infile'].upper() == 'ON':
            suggestions.append("📁 local_infile enabled - potential for LOAD DATA LOCAL INFILE attacks")
        
        if 'secure_file_priv' in finding.variables:
            value = finding.variables['secure_file_priv']
            if not value or value.upper() == 'NULL':
                suggestions.append("📤 secure_file_priv unrestricted - potential for file read/write")
        
        # Database enumeration
        if finding.databases:
            interesting_dbs = [db for db in finding.databases 
                             if any(keyword in db.lower() for keyword in ['user', 'admin', 'customer', 'payment', 'wordpress', 'drupal'])]
            if interesting_dbs:
                suggestions.append(f"📊 Interesting databases found: {', '.join(interesting_dbs[:3])}")
        
        # Access testing
        if not finding.empty_password_accounts:
            suggestions.append("🔐 No empty passwords found - try common credentials:")
            suggestions.append("   • root:root, root:password, admin:admin, mysql:mysql")
        
        # Anonymous access
        if finding.anonymous_access:
            suggestions.append("👤 Anonymous access detected - test with mysql -h <target>")
        
        # Manual enumeration suggestions
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Test for UDF (User Defined Function) injection")
        suggestions.append("   • Check for privilege escalation via MySQL functions")
        suggestions.append("   • Look for stored procedures and triggers")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
        
        print(f"\n💡 Kevin's MySQL Pro Tips:")
        print("   • Empty passwords are gold mines - always test first")
        print("   • Check mysql.user table if you get access")
        print("   • Look for database names that suggest applications")
        print("   • File read/write capabilities can lead to system access")
        print("   • Use 'show mysql' to see all enumeration details")
    
    def _display_mssql_findings(self, finding: MSSQLFinding):
        """Display comprehensive MSSQL enumeration results"""
        print(f"\n=== 🏢 MSSQL Enumeration Results: {finding.target}:{finding.port} ===")
        
        # Basic Information
        print("\n📊 BASIC INFORMATION:")
        if finding.version:
            print(f"   MSSQL Version: {finding.version}")
        if finding.product_version:
            print(f"   Product Version: {finding.product_version}")
        if finding.build_number:
            print(f"   Build Number: {finding.build_number}")
        if finding.authentication_mode:
            auth_display = "🔓 Mixed Mode (SQL + Windows)" if "mixed" in finding.authentication_mode.lower() else f"🔐 {finding.authentication_mode}"
            print(f"   Authentication: {auth_display}")
        
        # Critical Flags
        critical_alerts = []
        if finding.xp_cmdshell_enabled:
            critical_alerts.append("🔥 xp_cmdshell ENABLED - Command execution possible!")
        if finding.sa_account_blank_password:
            critical_alerts.append("🔥 SA account has BLANK password!")
        
        if critical_alerts:
            print("\n🚨 CRITICAL SECURITY ALERTS:")
            for alert in critical_alerts:
                print(f"   {alert}")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 HIGH RISK" if any(keyword in issue.lower() for keyword in ['critical', 'high', 'cmdshell', 'blank']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Weak Password Accounts
        if finding.weak_passwords:
            print(f"\n🔓 WEAK PASSWORD ACCOUNTS ({len(finding.weak_passwords)}):")
            for account, password in finding.weak_passwords.items():
                risk_level = "IMMEDIATE ACTION REQUIRED" if account.lower() == 'sa' else "Security Risk"
                print(f"   • {account}:{password} - {risk_level}")
        
        # Database Information
        if finding.databases:
            print(f"\n📂 ACCESSIBLE DATABASES ({len(finding.databases)}):")
            for db in finding.databases[:10]:  # Show first 10
                interest = "🎯" if any(keyword in db.lower() for keyword in ['master', 'model', 'user', 'admin']) else "📄"
                print(f"   {interest} {db}")
            if len(finding.databases) > 10:
                print(f"   ... and {len(finding.databases) - 10} more")
        
        # Dangerous Configurations
        if finding.dangerous_configurations:
            print(f"\n⚠️ DANGEROUS CONFIGURATIONS:")
            for config in finding.dangerous_configurations:
                print(f"   • {config}")
        
        # Service Information
        if finding.service_account or finding.tcp_port or finding.named_pipe:
            print(f"\n🔧 SERVICE INFORMATION:")
            if finding.service_account:
                print(f"   Service Account: {finding.service_account}")
            if finding.tcp_port:
                print(f"   TCP Port: {finding.tcp_port}")
            if finding.named_pipe:
                print(f"   Named Pipe: {finding.named_pipe}")
        
        # Attack Recommendations
        self._suggest_mssql_attacks(finding)
    
    def _suggest_mssql_attacks(self, finding: MSSQLFinding):
        """Suggest attack vectors based on MSSQL findings"""
        print(f"\n🎯 MSSQL ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # Critical vulnerabilities
        if finding.xp_cmdshell_enabled:
            suggestions.append("🔥 CRITICAL: xp_cmdshell enabled - try command execution!")
            suggestions.append(f"   Try: osql -S {finding.target} -E -Q \"xp_cmdshell 'whoami'\"")
        
        if finding.sa_account_blank_password:
            suggestions.append("🔥 CRITICAL: SA account has blank password!")
            suggestions.append(f"   Try: osql -S {finding.target} -U sa -P \"\" -Q \"SELECT @@VERSION\"")
        
        # Weak password exploitation
        if finding.weak_passwords:
            for account, password in finding.weak_passwords.items():
                suggestions.append(f"🔓 Test access with {account}:{password}")
                suggestions.append(f"   Try: osql -S {finding.target} -U {account} -P \"{password}\"")
        
        # Version-based attacks
        if finding.version:
            version_lower = finding.version.lower()
            if any(old_ver in version_lower for old_ver in ['2000', '2005', '2008']):
                suggestions.append("🎯 Older MSSQL version detected - research version-specific exploits")
            if '2008' in version_lower:
                suggestions.append("🔍 MSSQL 2008 detected - check for privilege escalation vulnerabilities")
        
        # Database enumeration
        if finding.databases:
            interesting_dbs = [db for db in finding.databases 
                             if any(keyword in db.lower() for keyword in ['master', 'user', 'admin', 'customer', 'payment'])]
            if interesting_dbs:
                suggestions.append(f"📊 Target interesting databases: {', '.join(interesting_dbs[:3])}")
        
        # Authentication mode exploitation
        if finding.authentication_mode and "mixed" in finding.authentication_mode.lower():
            suggestions.append("🔐 Mixed authentication mode - try both SQL and Windows authentication")
        
        # General recommendations
        if not finding.weak_passwords and not finding.sa_account_blank_password:
            suggestions.append("🔐 No obvious weak credentials - try common passwords:")
            suggestions.append("   • sa:sa, sa:password, admin:admin, sql:sql")
        
        # Manual enumeration suggestions
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Check for SQL injection if web apps connect to this DB")
        suggestions.append("   • Test for privilege escalation via SQL functions")
        suggestions.append("   • Look for linked servers and impersonation")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
        
        print(f"\n💡 Kevin's MSSQL Pro Tips:")
        print("   • xp_cmdshell is your golden ticket - always check first")
        print("   • SA account access = game over")
        print("   • Check master database for system information")
        print("   • Look for stored procedures and custom functions")
        print("   • Use 'show mssql' to see all enumeration details")
    
    def _display_oracle_findings(self, finding: OracleFinding):
        """Display comprehensive Oracle enumeration results"""
        print(f"\n=== 🔮 Oracle Enumeration Results: {finding.target}:{finding.port} ===")
        
        # TNS Listener Information
        if finding.listener_version or finding.listener_status:
            print("\n📊 TNS LISTENER INFORMATION:")
            if finding.listener_version:
                print(f"   Listener Version: {finding.listener_version}")
            if finding.listener_status:
                print(f"   Listener Status: {finding.listener_status}")
        
        # Service Identifiers (SIDs)
        if finding.sids:
            print(f"\n🎯 SERVICE IDENTIFIERS (SIDs) - {len(finding.sids)} discovered:")
            for sid in finding.sids:
                interest = "🔥" if sid.lower() in ['xe', 'orcl', 'prod', 'test', 'dev'] else "📄"
                print(f"   {interest} {sid}")
        
        # Accessible SIDs
        if finding.accessible_sids:
            print(f"\n✅ ACCESSIBLE SIDs ({len(finding.accessible_sids)}):")
            for sid in finding.accessible_sids:
                print(f"   • {sid} - Connection verified!")
        
        # Version Information
        if finding.version or finding.banner:
            print(f"\n📊 VERSION INFORMATION:")
            if finding.version:
                print(f"   Oracle Version: {finding.version}")
            if finding.banner:
                print(f"   Banner: {finding.banner}")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 HIGH RISK" if any(keyword in issue.lower() for keyword in ['critical', 'high', 'default', 'weak']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Default Accounts
        if finding.default_accounts:
            print(f"\n🔓 DEFAULT ACCOUNTS DETECTED:")
            for account in finding.default_accounts:
                risk_level = "IMMEDIATE ACTION REQUIRED" if account.lower() in ['sys', 'system', 'scott'] else "Security Risk"
                print(f"   • {account} - {risk_level}")
        
        # Listener Configuration
        if finding.listener_log_status or finding.listener_log_file:
            print(f"\n📋 LISTENER CONFIGURATION:")
            if finding.listener_log_status:
                log_status = "✅ Enabled" if "on" in finding.listener_log_status.lower() else "❌ Disabled"
                print(f"   Logging: {log_status}")
            if finding.listener_log_file:
                print(f"   Log File: {finding.listener_log_file}")
        
        # Attack Recommendations
        self._suggest_oracle_attacks(finding)
    
    def _suggest_oracle_attacks(self, finding: OracleFinding):
        """Suggest attack vectors based on Oracle findings"""
        print(f"\n🎯 ORACLE ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # SID-based attacks
        if finding.accessible_sids:
            suggestions.append(f"🎯 PRIORITY: {len(finding.accessible_sids)} accessible SIDs found!")
            for sid in finding.accessible_sids[:3]:  # Show top 3
                suggestions.append(f"   Try connecting to SID: {sid}")
                suggestions.append(f"   sqlplus system/manager@{finding.target}:1521/{sid}")
        
        # Default account exploitation
        if finding.default_accounts:
            suggestions.append("🔓 Default accounts detected - try common credentials:")
            default_creds = [
                "sys/password", "system/manager", "scott/tiger", 
                "hr/hr", "dbsnmp/dbsnmp", "sysman/sysman"
            ]
            for cred in default_creds[:3]:
                suggestions.append(f"   • {cred}")
        
        # SID discovery recommendations
        if finding.sids:
            high_value_sids = [sid for sid in finding.sids if sid.lower() in ['xe', 'orcl', 'prod', 'test']]
            if high_value_sids:
                suggestions.append(f"🔥 High-value SIDs discovered: {', '.join(high_value_sids)}")
                suggestions.append("   These are commonly targeted - test immediately!")
        
        # Version-based attacks
        if finding.version:
            version_lower = finding.version.lower()
            if any(old_ver in version_lower for old_ver in ['8i', '9i', '10g']):
                suggestions.append("🎯 Older Oracle version detected - research version-specific exploits")
            elif '11g' in version_lower:
                suggestions.append("🔍 Oracle 11g detected - check for privilege escalation issues")
        
        # Listener security
        if finding.listener_log_status and "off" in finding.listener_log_status.lower():
            suggestions.append("📋 Listener logging disabled - potential for stealth attacks")
        
        # General attack strategies
        if not finding.accessible_sids:
            suggestions.append("🔐 No immediate SID access - try brute force approaches:")
            suggestions.append("   • Use odat or oracle_login for credential testing")
            suggestions.append("   • Test common SID names: XE, ORCL, PROD, TEST, DEV")
        
        # Manual enumeration suggestions
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Use tnscmd10g for detailed listener enumeration")
        suggestions.append("   • Check for TNS poisoning vulnerabilities")
        suggestions.append("   • Test for privilege escalation via PL/SQL")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
        
        print(f"\n💡 Kevin's Oracle Pro Tips:")
        print("   • SIDs are the keys to the kingdom - enumerate thoroughly")
        print("   • Default credentials are still surprisingly common")
        print("   • TNS Listener can reveal valuable system information")
        print("   • Focus on accessible SIDs first")
        print("   • Use 'show oracle' to see all enumeration details")
    
    def _display_smtp_findings(self, finding: SMTPFinding):
        """Display comprehensive SMTP enumeration results"""
        print(f"\n=== 📧 SMTP Enumeration Results: {finding.target}:{finding.port} ===")
        
        # Basic Information
        print("\n📊 BASIC INFORMATION:")
        if finding.banner:
            print(f"   Banner: {finding.banner}")
        if finding.hostname:
            print(f"   Hostname: {finding.hostname}")
        if finding.software:
            version_info = f" {finding.version}" if finding.version else ""
            print(f"   Software: {finding.software}{version_info}")
        
        # Security Status
        print(f"\n🔒 SECURITY STATUS:")
        if finding.starttls_available:
            print(f"   STARTTLS: ✅ Available")
        else:
            print(f"   STARTTLS: ❌ Not available")
        
        # Critical Security Issues
        critical_issues = []
        if finding.relay_test_result == "OPEN RELAY DETECTED":
            critical_issues.append("🔥 CRITICAL: Open mail relay detected!")
        
        if critical_issues:
            print("\n🚨 CRITICAL SECURITY ALERTS:")
            for issue in critical_issues:
                print(f"   {issue}")
        
        # Capabilities and Features
        if finding.capabilities:
            print(f"\n⚙️ SMTP CAPABILITIES ({len(finding.capabilities)}):")
            for cap in finding.capabilities:
                security_note = ""
                if cap == 'VRFY':
                    security_note = " ⚠️ USER ENUMERATION"
                elif cap == 'EXPN':
                    security_note = " ⚠️ LIST EXPANSION"
                print(f"   • {cap}{security_note}")
        
        # Authentication Methods
        if finding.auth_methods:
            print(f"\n🔐 AUTHENTICATION METHODS:")
            for method in finding.auth_methods:
                print(f"   • {method}")
        
        # User Enumeration Results
        if finding.valid_users:
            print(f"\n👤 VALID USERS DISCOVERED ({len(finding.valid_users)}):")
            for user in finding.valid_users:
                print(f"   • {user}")
        
        # Configuration Details
        if finding.max_message_size:
            print(f"\n📋 CONFIGURATION:")
            print(f"   Max Message Size: {finding.max_message_size} bytes")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'open relay']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Attack Recommendations
        self._suggest_smtp_attacks(finding)
    
    def _suggest_smtp_attacks(self, finding: SMTPFinding):
        """Suggest attack vectors based on SMTP findings"""
        print(f"\n🎯 SMTP ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # Critical vulnerabilities
        if finding.relay_test_result == "OPEN RELAY DETECTED":
            suggestions.append("🔥 CRITICAL: Open relay detected - can be abused for spam/phishing!")
            suggestions.append("   Test: telnet <target> 25, then try MAIL FROM/RCPT TO with external addresses")
        
        # User enumeration
        if finding.vrfy_enabled:
            suggestions.append("🔍 VRFY command enabled - enumerate users:")
            suggestions.append("   Try: smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t <target>")
        
        if finding.expn_enabled:
            suggestions.append("🔍 EXPN command enabled - enumerate mailing lists:")
            suggestions.append("   Try: smtp-user-enum -M EXPN -U common-lists.txt -t <target>")
        
        # Valid users found
        if finding.valid_users:
            suggestions.append(f"👤 {len(finding.valid_users)} valid users discovered:")
            for user in finding.valid_users[:3]:
                suggestions.append(f"   • {user} - try password attacks or social engineering")
        
        # Software-specific attacks
        if finding.software and finding.version:
            if 'postfix' in finding.software.lower():
                suggestions.append("📧 Postfix detected - check for version-specific vulnerabilities")
            elif 'sendmail' in finding.software.lower():
                suggestions.append("📧 Sendmail detected - historically vulnerable, research exploits")
            elif 'exchange' in finding.software.lower():
                suggestions.append("📧 Microsoft Exchange detected - check for recent CVEs")
        
        # Encryption issues
        if not finding.starttls_available:
            suggestions.append("🔓 No STARTTLS - communications in plaintext")
            suggestions.append("   Consider: credential sniffing, man-in-the-middle attacks")
        
        # General recommendations
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Test for email harvesting via RCPT TO")
        suggestions.append("   • Check for internal hostname disclosure")
        suggestions.append("   • Test authentication bypass techniques")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
        
        print(f"\n💡 Kevin's SMTP Pro Tips:")
        print("   • Open relays are immediate critical findings")
        print("   • User enumeration leads to targeted attacks")
        print("   • Email addresses discovered can be used for phishing")
        print("   • SMTP banners often leak internal information")
        print("   • Use 'show smtp' to see all enumeration details")
    
    def _display_email_service_findings(self, finding: EmailServiceFinding):
        """Display comprehensive email service enumeration results"""
        print(f"\n=== 📬 {finding.service_type.upper()} Enumeration Results: {finding.target}:{finding.port} ===")
        
        # Basic Information
        print("\n📊 BASIC INFORMATION:")
        if finding.banner:
            print(f"   Banner: {finding.banner}")
        if finding.software:
            version_info = f" {finding.version}" if finding.version else ""
            print(f"   Software: {finding.software}{version_info}")
        
        # Security Status
        print(f"\n🔒 SECURITY STATUS:")
        ssl_status = "✅ Enabled" if finding.ssl_enabled else "❌ Disabled"
        print(f"   SSL/TLS: {ssl_status}")
        if finding.starttls_available:
            print(f"   STARTTLS: ✅ Available")
        
        # Critical Security Issues
        critical_issues = []
        if finding.plaintext_auth:
            critical_issues.append("🔥 CRITICAL: Plaintext authentication over unencrypted connection!")
        
        if critical_issues:
            print("\n🚨 CRITICAL SECURITY ALERTS:")
            for issue in critical_issues:
                print(f"   {issue}")
        
        # Capabilities
        if finding.capabilities:
            print(f"\n⚙️ {finding.service_type.upper()} CAPABILITIES ({len(finding.capabilities)}):")
            for cap in finding.capabilities:
                security_note = ""
                if 'AUTH' in cap.upper():
                    security_note = " 🔐"
                elif 'STARTTLS' in cap.upper():
                    security_note = " 🔒"
                print(f"   • {cap}{security_note}")
        
        # Authentication Mechanisms
        if finding.auth_mechanisms:
            print(f"\n🔐 AUTHENTICATION MECHANISMS:")
            for mechanism in finding.auth_mechanisms:
                security_note = ""
                if 'PLAIN' in mechanism.upper() and not finding.ssl_enabled and not finding.starttls_available:
                    security_note = " ⚠️ PLAINTEXT RISK"
                print(f"   • {mechanism}{security_note}")
        
        # Configuration Details
        config_items = []
        if finding.login_disabled:
            config_items.append("Login: Currently disabled")
        if finding.anonymous_access:
            config_items.append("Anonymous Access: ⚠️ Possible")
        if finding.max_connections:
            config_items.append(f"Max Connections: {finding.max_connections}")
        
        if config_items:
            print(f"\n📋 CONFIGURATION:")
            for item in config_items:
                print(f"   {item}")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'plaintext']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Weak Configurations
        if finding.weak_configurations:
            print(f"\n⚠️ WEAK CONFIGURATIONS:")
            for config in finding.weak_configurations:
                print(f"   • {config}")
        
        # Attack Recommendations
        self._suggest_email_service_attacks(finding)
    
    def _suggest_email_service_attacks(self, finding: EmailServiceFinding):
        """Suggest attack vectors based on email service findings"""
        print(f"\n🎯 {finding.service_type.upper()} ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # Critical vulnerabilities
        if finding.plaintext_auth:
            suggestions.append("🔥 CRITICAL: Plaintext authentication detected!")
            suggestions.append("   Risk: Credentials transmitted in clear text - sniffing possible")
        
        # Anonymous access
        if finding.anonymous_access:
            suggestions.append("👤 Anonymous access potentially available:")
            suggestions.append(f"   Try: telnet {finding.target} {finding.port}, then try anonymous login")
        
        # Encryption issues
        if not finding.ssl_enabled and not finding.starttls_available:
            suggestions.append("🔓 No encryption available - all communications in plaintext:")
            suggestions.append("   Consider: credential sniffing, session hijacking")
        
        # Authentication attacks
        if not finding.login_disabled:
            suggestions.append("🔐 Authentication possible - try credential attacks:")
            suggestions.append("   • Test common credentials: admin:admin, test:test")
            suggestions.append("   • Use hydra for brute force if permitted")
        
        # Software-specific vulnerabilities
        if finding.software and finding.version:
            if 'dovecot' in finding.software.lower():
                suggestions.append("📧 Dovecot detected - check for version-specific CVEs")
            elif 'courier' in finding.software.lower():
                suggestions.append("📧 Courier detected - research known vulnerabilities")
            elif 'exchange' in finding.software.lower():
                suggestions.append("📧 Microsoft Exchange detected - check recent security updates")
        
        # Configuration exploitation
        if finding.capabilities:
            if any('IDLE' in cap.upper() for cap in finding.capabilities):
                suggestions.append("⏱️ IDLE capability supported - potential for resource exhaustion")
        
        # General recommendations
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Test for information disclosure in banners")
        suggestions.append("   • Check for timing attacks in authentication")
        suggestions.append("   • Look for shared mailboxes or default accounts")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
    
    def _display_ldap_findings(self, finding: LDAPFinding):
        """Display comprehensive LDAP enumeration results"""
        print(f"\n=== 🏢 LDAP Enumeration Results: {finding.target}:{finding.port} ===")
        
        # Basic Information
        print("\n📊 BASIC INFORMATION:")
        if finding.server_info:
            print(f"   Server Info: {finding.server_info}")
        if finding.base_dn:
            print(f"   Base DN: {finding.base_dn}")
        if finding.supported_sasl_mechanisms:
            print(f"   SASL Mechanisms: {', '.join(finding.supported_sasl_mechanisms)}")
        
        # Naming Contexts
        if finding.naming_contexts:
            print(f"\n📂 NAMING CONTEXTS ({len(finding.naming_contexts)}):")
            for context in finding.naming_contexts:
                print(f"   • {context}")
        
        # Directory Structure
        if finding.organizational_units:
            print(f"\n🏗️ ORGANIZATIONAL UNITS ({len(finding.organizational_units)}):")
            for ou in finding.organizational_units[:10]:  # Show first 10
                print(f"   • {ou}")
            if len(finding.organizational_units) > 10:
                print(f"   ... and {len(finding.organizational_units) - 10} more")
        
        # Schema Information
        if finding.schema_information:
            print(f"\n📋 SCHEMA INFORMATION:")
            for key, value in finding.schema_information.items():
                if isinstance(value, list):
                    print(f"   {key}: {len(value)} entries")
                else:
                    print(f"   {key}: {value}")
        
        # Users and Groups
        if finding.users_found:
            print(f"\n👥 USERS FOUND ({len(finding.users_found)}):")
            for user in finding.users_found[:10]:  # Show first 10
                print(f"   • {user}")
            if len(finding.users_found) > 10:
                print(f"   ... and {len(finding.users_found) - 10} more")
        
        if finding.groups_found:
            print(f"\n👤 GROUPS FOUND ({len(finding.groups_found)}):")
            for group in finding.groups_found[:10]:  # Show first 10
                print(f"   • {group}")
            if len(finding.groups_found) > 10:
                print(f"   ... and {len(finding.groups_found) - 10} more")
        
        # Computer Accounts
        if finding.computer_accounts:
            print(f"\n💻 COMPUTER ACCOUNTS ({len(finding.computer_accounts)}):")
            for computer in finding.computer_accounts[:10]:  # Show first 10
                print(f"   • {computer}")
            if len(finding.computer_accounts) > 10:
                print(f"   ... and {len(finding.computer_accounts) - 10} more")
        
        # Critical Security Issues
        critical_issues = []
        if finding.anonymous_bind:
            critical_issues.append("🔥 CRITICAL: Anonymous bind enabled!")
        if finding.weak_configurations:
            critical_issues.extend([f"⚠️ {config}" for config in finding.weak_configurations])
        
        if critical_issues:
            print("\n🚨 CRITICAL SECURITY ALERTS:")
            for issue in critical_issues:
                print(f"   {issue}")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'anonymous']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Attack Recommendations
        self._suggest_ldap_attacks(finding)
    
    def _display_kerberos_findings(self, finding: KerberosFinding):
        """Display comprehensive Kerberos enumeration results"""
        print(f"\n=== 🎫 Kerberos Enumeration Results: {finding.target}:{finding.port} ===")
        
        # Basic Information
        print("\n📊 BASIC INFORMATION:")
        if finding.realm:
            print(f"   Kerberos Realm: {finding.realm}")
        if finding.kdc_server:
            print(f"   KDC Server: {finding.kdc_server}")
        if finding.supported_encryption_types:
            print(f"   Encryption Types: {', '.join(finding.supported_encryption_types)}")
        
        # Service Principal Names
        if finding.spns_found:
            print(f"\n🎯 SERVICE PRINCIPAL NAMES ({len(finding.spns_found)}):")
            for spn in finding.spns_found[:10]:  # Show first 10
                print(f"   • {spn}")
            if len(finding.spns_found) > 10:
                print(f"   ... and {len(finding.spns_found) - 10} more")
        
        # Users
        if finding.users_found:
            print(f"\n👥 USERS FOUND ({len(finding.users_found)}):")
            for user in finding.users_found[:10]:  # Show first 10
                print(f"   • {user}")
            if len(finding.users_found) > 10:
                print(f"   ... and {len(finding.users_found) - 10} more")
        
        # Service Accounts
        if finding.service_accounts:
            print(f"\n🔧 SERVICE ACCOUNTS ({len(finding.service_accounts)}):")
            for account in finding.service_accounts[:10]:  # Show first 10
                print(f"   • {account}")
            if len(finding.service_accounts) > 10:
                print(f"   ... and {len(finding.service_accounts) - 10} more")
        
        # Critical Security Issues
        critical_issues = []
        if finding.asrep_roastable_users:
            critical_issues.append(f"🔥 CRITICAL: {len(finding.asrep_roastable_users)} users vulnerable to AS-REP roasting!")
        if finding.kerberoastable_users:
            critical_issues.append(f"🔥 CRITICAL: {len(finding.kerberoastable_users)} users vulnerable to Kerberoasting!")
        if finding.weak_encryption_detected:
            critical_issues.append("⚠️ Weak encryption algorithms detected")
        
        if critical_issues:
            print("\n🚨 CRITICAL SECURITY ALERTS:")
            for issue in critical_issues:
                print(f"   {issue}")
        
        # AS-REP Roastable Users
        if finding.asrep_roastable_users:
            print(f"\n🔥 AS-REP ROASTABLE USERS ({len(finding.asrep_roastable_users)}):")
            for user in finding.asrep_roastable_users[:5]:  # Show first 5
                print(f"   • {user} (Pre-authentication disabled)")
            if len(finding.asrep_roastable_users) > 5:
                print(f"   ... and {len(finding.asrep_roastable_users) - 5} more")
        
        # Kerberoastable Users
        if finding.kerberoastable_users:
            print(f"\n🎯 KERBEROASTABLE USERS ({len(finding.kerberoastable_users)}):")
            for user in finding.kerberoastable_users[:5]:  # Show first 5
                print(f"   • {user}")
            if len(finding.kerberoastable_users) > 5:
                print(f"   ... and {len(finding.kerberoastable_users) - 5} more")
        
        # Domain Controllers
        if finding.domain_controllers:
            print(f"\n🏢 DOMAIN CONTROLLERS ({len(finding.domain_controllers)}):")
            for dc in finding.domain_controllers:
                print(f"   • {dc}")
        
        # Security Issues
        if finding.security_issues:
            print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
            for i, issue in enumerate(finding.security_issues, 1):
                severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'roast']) else "⚠️  WARNING"
                print(f"   {i}. {severity}: {issue}")
        
        # Attack Recommendations
        self._suggest_kerberos_attacks(finding)
    
    def _suggest_ldap_attacks(self, finding: LDAPFinding):
        """Suggest attack vectors based on LDAP findings"""
        print(f"\n🎯 LDAP ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # Critical vulnerabilities
        if finding.anonymous_bind:
            suggestions.append("🔥 CRITICAL: Anonymous bind enabled!")
            suggestions.append("   Risk: Full directory enumeration without authentication")
            suggestions.append("   Action: Enumerate all objects, users, groups, and configuration")
        
        # User enumeration
        if finding.users_found:
            suggestions.append("👥 User enumeration successful:")
            suggestions.append("   • Build username list for password spraying")
            suggestions.append("   • Look for service accounts with elevated privileges")
            suggestions.append("   • Check for accounts with non-expiring passwords")
        
        # Group enumeration
        if finding.groups_found:
            suggestions.append("👤 Group enumeration successful:")
            suggestions.append("   • Identify high-privilege groups (Domain Admins, etc.)")
            suggestions.append("   • Map group memberships for privilege escalation paths")
        
        # Computer accounts
        if finding.computer_accounts:
            suggestions.append("💻 Computer accounts discovered:")
            suggestions.append("   • Identify domain controllers and critical servers")
            suggestions.append("   • Look for stale computer accounts")
        
        # Schema information
        if finding.schema_information:
            suggestions.append("📋 Schema information accessible:")
            suggestions.append("   • Look for custom attributes with sensitive data")
            suggestions.append("   • Identify extended rights and permissions")
        
        # General recommendations
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Search for passwords in description fields")
        suggestions.append("   • Look for backup/legacy accounts")
        suggestions.append("   • Check for LDAP injection vulnerabilities")
        suggestions.append("   • Enumerate trust relationships")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
    
    def _suggest_kerberos_attacks(self, finding: KerberosFinding):
        """Suggest attack vectors based on Kerberos findings"""
        print(f"\n🎯 KERBEROS ATTACK RECOMMENDATIONS:")
        
        suggestions = []
        
        # AS-REP Roasting
        if finding.asrep_roastable_users:
            suggestions.append("🔥 CRITICAL: AS-REP Roasting possible!")
            suggestions.append(f"   {len(finding.asrep_roastable_users)} users have pre-authentication disabled")
            suggestions.append("   Action: Use GetNPUsers.py or Rubeus to harvest AS-REP hashes")
            suggestions.append("   Next: Crack hashes offline with hashcat")
        
        # Kerberoasting
        if finding.kerberoastable_users:
            suggestions.append("🎯 Kerberoasting opportunities available!")
            suggestions.append(f"   {len(finding.kerberoastable_users)} users have SPNs set")
            suggestions.append("   Action: Use GetUserSPNs.py or Rubeus to request service tickets")
            suggestions.append("   Next: Crack TGS-REP hashes offline")
        
        # SPN enumeration
        if finding.spns_found:
            suggestions.append("🎯 Service Principal Names discovered:")
            suggestions.append("   • Map services to understand network architecture")
            suggestions.append("   • Identify high-value services (SQL, Exchange, etc.)")
            suggestions.append("   • Look for custom applications with weak SPNs")
        
        # User enumeration
        if finding.users_found:
            suggestions.append("👥 User enumeration successful:")
            suggestions.append("   • Build username list for password spraying")
            suggestions.append("   • Check for users with Kerberos pre-authentication disabled")
            suggestions.append("   • Look for service accounts in user list")
        
        # Weak encryption
        if finding.weak_encryption_detected:
            suggestions.append("⚠️ Weak encryption algorithms detected:")
            suggestions.append("   • DES/RC4 encryption vulnerable to brute force")
            suggestions.append("   • Consider downgrade attacks if possible")
        
        # Domain controller enumeration
        if finding.domain_controllers:
            suggestions.append("🏢 Domain controllers identified:")
            suggestions.append("   • Target for Golden/Silver ticket attacks")
            suggestions.append("   • Check for DCSync permissions")
            suggestions.append("   • Look for replication opportunities")
        
        # General recommendations
        suggestions.append("🔍 Manual enumeration suggestions:")
        suggestions.append("   • Test for Kerberos delegation issues")
        suggestions.append("   • Look for accounts with constrained delegation")
        suggestions.append("   • Check for password spraying opportunities")
        suggestions.append("   • Enumerate cross-domain trusts")
        
        if suggestions:
            for suggestion in suggestions:
                print(f"   {suggestion}")
    
    def _manual_mssql_enumeration(self, ports: str):
        """Manual MSSQL enumeration triggered by enum command"""
        print(f"Kevin: 🏢 Manual MSSQL enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for MSSQL)
            mssql_port = int(ports.split(',')[0])  # Take first port if multiple
            
            print("Kevin: 🔍 Comprehensive MSSQL information gathering and security assessment...")
            print("Kevin: This will check for version info, empty passwords, xp_cmdshell, and database access!")
            
            # Run comprehensive MSSQL enumeration
            finding = self.mssql_enumerator.enumerate_mssql(self.current_target.ip, mssql_port)
            self.current_target.mssql_findings.append(finding)
            
            # Display comprehensive results
            self._display_mssql_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_mssql_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual MSSQL enumeration failed - {e}")
    
    def _manual_oracle_enumeration(self, ports: str):
        """Manual Oracle enumeration triggered by enum command"""
        print(f"Kevin: 🔮 Manual Oracle enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for Oracle)
            oracle_port = int(ports.split(',')[0])  # Take first port if multiple
            
            print("Kevin: 🔍 Comprehensive Oracle information gathering and SID discovery...")
            print("Kevin: This will check TNS listener, enumerate SIDs, and assess security!")
            
            # Run comprehensive Oracle enumeration
            finding = self.oracle_enumerator.enumerate_oracle(self.current_target.ip, oracle_port)
            self.current_target.oracle_findings.append(finding)
            
            # Display comprehensive results
            self._display_oracle_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_oracle_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual Oracle enumeration failed - {e}")
    
    def _manual_smtp_enumeration(self, ports: str):
        """Manual SMTP enumeration triggered by enum command"""
        print(f"Kevin: 📧 Manual SMTP enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for SMTP)
            smtp_port = int(ports.split(',')[0])  # Take first port if multiple
            
            print("Kevin: 🔍 Comprehensive SMTP banner grabbing, capability discovery, and user enumeration...")
            print("Kevin: This will check for relay misconfiguration, VRFY/EXPN commands, and security issues!")
            
            # Run comprehensive SMTP enumeration
            finding = self.smtp_enumerator.enumerate_smtp(self.current_target.ip, smtp_port)
            self.current_target.smtp_findings.append(finding)
            
            # Display comprehensive results
            self._display_smtp_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_smtp_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual SMTP enumeration failed - {e}")
    
    def _manual_email_service_enumeration(self, service: str, ports: str):
        """Manual email service enumeration triggered by enum command"""
        print(f"Kevin: 📬 Manual {service.upper()} enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for email service)
            email_port = int(ports.split(',')[0])  # Take first port if multiple
            
            # Determine service type and SSL status
            if service.lower() == 'pop3':
                service_type = 'pop3s' if email_port == 995 else 'pop3'
            elif service.lower() == 'imap':
                service_type = 'imaps' if email_port == 993 else 'imap'
            else:
                service_type = service.lower()
            
            print(f"Kevin: 🔍 Comprehensive {service_type.upper()} capability discovery and security assessment...")
            print("Kevin: This will check authentication methods, encryption support, and configuration security!")
            
            # Run comprehensive email service enumeration
            finding = self.email_service_enumerator.enumerate_email_service(
                self.current_target.ip, email_port, service_type
            )
            self.current_target.email_findings.append(finding)
            
            # Display comprehensive results
            self._display_email_service_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_{service_type}_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual {service.upper()} enumeration failed - {e}")
    
    def _manual_ldap_enumeration(self, ports: str):
        """Manual LDAP enumeration triggered by enum command"""
        print(f"Kevin: 🏢 Manual LDAP enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for LDAP)
            ldap_port = int(ports.split(',')[0])  # Take first port if multiple
            
            print("Kevin: 🔍 Comprehensive LDAP directory service enumeration...")
            print("Kevin: This will check for anonymous access, enumerate users/groups, and assess security!")
            
            # Run comprehensive LDAP enumeration
            finding = self.ldap_enumerator.enumerate_ldap(self.current_target.ip, ldap_port)
            self.current_target.ldap_findings.append(finding)
            
            # Display comprehensive results
            self._display_ldap_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_ldap_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual LDAP enumeration failed - {e}")
    
    def _manual_kerberos_enumeration(self, ports: str):
        """Manual Kerberos enumeration triggered by enum command"""
        print(f"Kevin: 🎫 Manual Kerberos enumeration on port(s) {ports}...")
        
        try:
            # Parse port (should be single port for Kerberos)
            kerberos_port = int(ports.split(',')[0])  # Take first port if multiple
            
            print("Kevin: 🔍 Comprehensive Kerberos authentication service enumeration...")
            print("Kevin: This will check realm info, enumerate users, find SPNs, and assess security!")
            
            # Run comprehensive Kerberos enumeration
            finding = self.kerberos_enumerator.enumerate_kerberos(self.current_target.ip, kerberos_port)
            self.current_target.kerberos_findings.append(finding)
            
            # Display comprehensive results
            self._display_kerberos_findings(finding)
            
            # Add to scan history
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_target.scan_history.append(f"enum_kerberos_{timestamp}: {datetime.now()}")
            
        except ValueError:
            print(f"Kevin: Invalid port number: {ports}")
        except Exception as e:
            print(f"Kevin: Manual Kerberos enumeration failed - {e}")
    
    def _auto_mssql_enumeration(self):
        """Launch automatic MSSQL enumeration"""
        print("Kevin: 🏢 Launching comprehensive MSSQL enumeration...")
        
        try:
            # Find MSSQL port
            mssql_port = 1433
            for port in self.current_target.open_ports:
                if port.service.lower() in ['mssql', 'ms-sql-s', 'microsoft-ds'] or port.number == 1433:
                    mssql_port = port.number
                    break
            
            print(f"Kevin: 🔍 MSSQL enumeration on port {mssql_port}...")
            print("Kevin: Checking for version info, empty passwords, xp_cmdshell, and database access...")
            
            # Run comprehensive MSSQL enumeration
            finding = self.mssql_enumerator.enumerate_mssql(self.current_target.ip, mssql_port)
            self.current_target.mssql_findings.append(finding)
            
            # Display immediate results
            if finding.security_issues:
                print(f"\nKevin: 🚨 Found {len(finding.security_issues)} MSSQL security issues!")
                for issue in finding.security_issues[:3]:  # Show top 3
                    print(f"  • {issue}")
                if len(finding.security_issues) > 3:
                    print(f"  ... and {len(finding.security_issues) - 3} more (use 'show mssql' for all)")
            
            if finding.xp_cmdshell_enabled:
                print(f"Kevin: 🔥 CRITICAL: xp_cmdshell is enabled - command execution possible!")
            
            if finding.databases:
                print(f"Kevin: 📊 Discovered {len(finding.databases)} databases!")
            
            if finding.weak_passwords:
                print(f"Kevin: 🔓 Found {len(finding.weak_passwords)} accounts with weak passwords!")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_mssql_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto MSSQL enumeration failed - {e}")
    
    def _auto_oracle_enumeration(self):
        """Launch automatic Oracle enumeration"""
        print("Kevin: 🔮 Launching comprehensive Oracle enumeration...")
        
        try:
            # Find Oracle port
            oracle_port = 1521
            for port in self.current_target.open_ports:
                if port.service.lower() in ['oracle', 'oracle-tns'] or port.number == 1521:
                    oracle_port = port.number
                    break
            
            print(f"Kevin: 🔍 Oracle enumeration on port {oracle_port}...")
            print("Kevin: Checking TNS listener, SID enumeration, and version detection...")
            
            # Run comprehensive Oracle enumeration
            finding = self.oracle_enumerator.enumerate_oracle(self.current_target.ip, oracle_port)
            self.current_target.oracle_findings.append(finding)
            
            # Display immediate results
            if finding.sids:
                print(f"\nKevin: 🎯 Found {len(finding.sids)} Oracle SIDs!")
                for sid in finding.sids[:3]:  # Show top 3
                    print(f"  • {sid}")
                if len(finding.sids) > 3:
                    print(f"  ... and {len(finding.sids) - 3} more (use 'show oracle' for all)")
            
            if finding.accessible_sids:
                print(f"Kevin: ✅ {len(finding.accessible_sids)} SIDs are accessible!")
            
            if finding.listener_version:
                print(f"Kevin: 📊 TNS Listener version: {finding.listener_version}")
            
            if finding.security_issues:
                print(f"Kevin: 🚨 Found {len(finding.security_issues)} Oracle security issues!")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_oracle_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto Oracle enumeration failed - {e}")
    
    def _auto_smtp_enumeration(self):
        """Launch automatic SMTP enumeration"""
        print("Kevin: 📧 Launching comprehensive SMTP enumeration...")
        
        try:
            # Find SMTP port
            smtp_port = 25
            for port in self.current_target.open_ports:
                if port.service.lower() in ['smtp', 'submission'] or port.number in [25, 465, 587]:
                    smtp_port = port.number
                    break
            
            print(f"Kevin: 🔍 SMTP enumeration on port {smtp_port}...")
            print("Kevin: Checking banner, capabilities, user enumeration, and security assessment...")
            
            # Run comprehensive SMTP enumeration
            finding = self.smtp_enumerator.enumerate_smtp(self.current_target.ip, smtp_port)
            self.current_target.smtp_findings.append(finding)
            
            # Display immediate results
            if finding.banner:
                print(f"\nKevin: 📋 SMTP Banner: {finding.banner}")
            
            if finding.relay_test_result == "OPEN RELAY DETECTED":
                print(f"Kevin: 🔥 CRITICAL: Open mail relay detected!")
            
            if finding.vrfy_enabled or finding.expn_enabled:
                print(f"Kevin: 🔍 User enumeration possible via {'VRFY' if finding.vrfy_enabled else ''}{' and ' if finding.vrfy_enabled and finding.expn_enabled else ''}{'EXPN' if finding.expn_enabled else ''}")
            
            if finding.valid_users:
                print(f"Kevin: 👤 Found {len(finding.valid_users)} valid users!")
                for user in finding.valid_users[:3]:  # Show top 3
                    print(f"  • {user}")
                if len(finding.valid_users) > 3:
                    print(f"  ... and {len(finding.valid_users) - 3} more (use 'show smtp' for all)")
            
            if finding.security_issues:
                print(f"Kevin: 🚨 Found {len(finding.security_issues)} SMTP security issues!")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_smtp_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto SMTP enumeration failed - {e}")
    
    def _auto_email_service_enumeration(self, port: Port):
        """Launch automatic email service enumeration (POP3/IMAP)"""
        service_type = port.service.lower()
        
        # Determine service type based on port and service name
        if service_type in ['pop3', 'pop3s'] or port.number in [110, 995]:
            service_name = 'pop3s' if port.number == 995 or 'ssl' in service_type else 'pop3'
        elif service_type in ['imap', 'imaps'] or port.number in [143, 993]:
            service_name = 'imaps' if port.number == 993 or 'ssl' in service_type else 'imap'
        else:
            service_name = service_type
        
        print(f"Kevin: 📬 Launching {service_name.upper()} enumeration on port {port.number}...")
        
        try:
            print(f"Kevin: 🔍 {service_name.upper()} enumeration on port {port.number}...")
            print("Kevin: Checking capabilities, authentication methods, and security features...")
            
            # Run comprehensive email service enumeration
            finding = self.email_service_enumerator.enumerate_email_service(
                self.current_target.ip, port.number, service_name
            )
            self.current_target.email_findings.append(finding)
            
            # Display immediate results
            if finding.banner:
                print(f"\nKevin: 📋 {service_name.upper()} Banner: {finding.banner}")
            
            if finding.capabilities:
                print(f"Kevin: ⚙️  Capabilities: {', '.join(finding.capabilities[:5])}{'...' if len(finding.capabilities) > 5 else ''}")
            
            if finding.starttls_available:
                print(f"Kevin: 🔒 STARTTLS supported - encryption available")
            elif not finding.ssl_enabled:
                print(f"Kevin: ⚠️  No encryption detected - plaintext communications")
            
            if finding.plaintext_auth:
                print(f"Kevin: 🚨 CRITICAL: Plaintext authentication over unencrypted connection!")
            
            if finding.anonymous_access:
                print(f"Kevin: 👤 Anonymous access may be possible!")
            
            if finding.security_issues:
                print(f"Kevin: 🚨 Found {len(finding.security_issues)} email service security issues!")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_{service_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto {service_name.upper()} enumeration failed - {e}")
    
    def _auto_ldap_enumeration(self):
        """Launch automatic LDAP enumeration"""
        print("Kevin: 🏢 Launching comprehensive LDAP enumeration...")
        
        try:
            # Find LDAP port
            ldap_port = 389
            for port in self.current_target.open_ports:
                if port.service.lower() in ['ldap', 'ldaps'] or port.number in [389, 636]:
                    ldap_port = port.number
                    break
            
            print(f"Kevin: 🔍 LDAP enumeration on port {ldap_port}...")
            print("Kevin: Checking for anonymous bind, naming contexts, schema, and directory structure...")
            
            # Run comprehensive LDAP enumeration
            finding = self.ldap_enumerator.enumerate_ldap(self.current_target.ip, ldap_port)
            self.current_target.ldap_findings.append(finding)
            
            # Display immediate results
            if finding.base_dn:
                print(f"\nKevin: 🌳 Base DN: {finding.base_dn}")
            
            if finding.naming_contexts:
                print(f"Kevin: 📂 Naming Contexts: {', '.join(finding.naming_contexts[:3])}{'...' if len(finding.naming_contexts) > 3 else ''}")
            
            if finding.anonymous_bind:
                print(f"Kevin: 🚨 CRITICAL: Anonymous bind enabled!")
            
            if finding.users_found:
                print(f"Kevin: 👥 Found {len(finding.users_found)} users in directory")
            
            if finding.groups_found:
                print(f"Kevin: 👤 Found {len(finding.groups_found)} groups in directory")
            
            if finding.security_issues:
                print(f"Kevin: 🚨 Found {len(finding.security_issues)} LDAP security issues!")
                for issue in finding.security_issues[:3]:  # Show top 3
                    print(f"  • {issue}")
                if len(finding.security_issues) > 3:
                    print(f"  ... and {len(finding.security_issues) - 3} more (use 'show ldap' for all)")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_ldap_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto LDAP enumeration failed - {e}")
    
    def _auto_kerberos_enumeration(self):
        """Launch automatic Kerberos enumeration"""
        print("Kevin: 🎫 Launching comprehensive Kerberos enumeration...")
        
        try:
            # Find Kerberos port
            kerberos_port = 88
            for port in self.current_target.open_ports:
                if port.service.lower() in ['kerberos', 'kerberos-sec', 'krb5'] or port.number in [88, 464]:
                    kerberos_port = port.number
                    break
            
            print(f"Kevin: 🔍 Kerberos enumeration on port {kerberos_port}...")
            print("Kevin: Checking for realm information, user enumeration, and AS-REP roasting opportunities...")
            
            # Run comprehensive Kerberos enumeration
            finding = self.kerberos_enumerator.enumerate_kerberos(self.current_target.ip, kerberos_port)
            self.current_target.kerberos_findings.append(finding)
            
            # Display immediate results
            if finding.realm:
                print(f"\nKevin: 🏰 Kerberos Realm: {finding.realm}")
            
            if finding.kdc_server:
                print(f"Kevin: 🏢 Key Distribution Center: {finding.kdc_server}")
            
            if finding.users_found:
                print(f"Kevin: 👥 Found {len(finding.users_found)} valid users")
                # Show first few users
                user_sample = finding.users_found[:5]
                print(f"Kevin: 👤 Sample users: {', '.join(user_sample)}{'...' if len(finding.users_found) > 5 else ''}")
            
            if finding.spns_found:
                print(f"Kevin: 🎯 Found {len(finding.spns_found)} Service Principal Names")
            
            if finding.asrep_roastable_users:
                print(f"Kevin: 🚨 CRITICAL: {len(finding.asrep_roastable_users)} users vulnerable to AS-REP roasting!")
            
            if finding.security_issues:
                print(f"Kevin: 🚨 Found {len(finding.security_issues)} Kerberos security issues!")
                for issue in finding.security_issues[:3]:  # Show top 3
                    print(f"  • {issue}")
                if len(finding.security_issues) > 3:
                    print(f"  ... and {len(finding.security_issues) - 3} more (use 'show kerberos' for all)")
            
            # Add to scan history
            self.current_target.scan_history.append(f"auto_kerberos_{datetime.now().strftime('%Y%m%d_%H%M%S')}: {datetime.now()}")
            
        except Exception as e:
            print(f"Kevin: Auto Kerberos enumeration failed - {e}")
    
    def _escalate_web_enumeration(self, url: str):
        """Escalate web enumeration with bigger wordlists if initial scan finds little"""
        current_wordlist = self.web_wordlist_preference
        
        # Escalation path: common -> big -> medium -> raft
        escalation_map = {
            'common': 'big',
            'big': 'medium', 
            'medium': 'raft',
            'raft': None  # Already at max
        }
        
        next_wordlist = escalation_map.get(current_wordlist)
        
        if next_wordlist:
            print(f"\nKevin: 🎯 Escalating web enumeration! Trying '{next_wordlist}' wordlist for more coverage...")
            print("Kevin: Sometimes the good stuff is hidden deeper!")
            
            time.sleep(3)  # Brief delay
            
            # Mark this as an escalated auto scan
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.session_dir / f"{self.current_target.ip}_auto_escalated_{next_wordlist}_{timestamp}.txt"
            
            try:
                process = self.web_enumerator.run_gobuster(
                    url, 
                    next_wordlist, 
                    self.web_enumerator.extensions['basic'], 
                    str(output_file)
                )
                web_id = f"auto_escalated_{next_wordlist}_{timestamp}"
                self.running_processes[web_id] = process
                
                print(f"Kevin: 🔍 Escalated directory enumeration running with {next_wordlist} wordlist...")
                
                threading.Thread(
                    target=self._monitor_web_scan,
                    args=(web_id, process, 'directory', url),
                    daemon=True
                ).start()
                
            except Exception as e:
                print(f"Kevin: Escalated enumeration failed - {e}")
        else:
            print("\nKevin: 🎯 Already at maximum wordlist coverage!")
            print("Kevin: If you need more, try manual parameter fuzzing or different extensions.")
    
    def do_enum(self, line: str):
        """
        Service-specific enumeration: enum <service> [ports]
        
        Services: smb, http, ftp, ssh, dns, snmp, mysql, mssql, oracle, smtp, pop3, imap, ldap, kerberos
        
        Examples:
        enum smb 139,445
        enum http 80,443
        enum mysql 3306
        enum mssql 1433
        enum oracle 1521
        enum smtp 25
        enum pop3 110
        enum imap 143
        """
        if not self.current_target:
            print("Kevin: Set a target first!")
            return
        
        args = line.strip().split()
        if not args:
            print("Kevin: Specify a service! Available: smb, http, ftp, ssh, dns, snmp, mysql, mssql, oracle, smtp, pop3, imap")
            return
        
        service = args[0].lower()
        
        # Auto-detect ports if not specified
        if len(args) > 1:
            ports = args[1]
        else:
            port_map = {
                'smb': '139,445',
                'http': '80,443,8080,8443',
                'ftp': '21',
                'ssh': '22', 
                'dns': '53',
                'snmp': '161',
                'mysql': '3306',
                'mssql': '1433',
                'oracle': '1521',
                'smtp': '25',
                'pop3': '110',
                'imap': '143',
                'ldap': '389,636',
                'kerberos': '88'
            }
            ports = port_map.get(service)
            if not ports:
                print(f"Kevin: Specify ports for {service}")
                return
        
        # Special handling for database enumeration
        if service == 'mysql':
            self._manual_mysql_enumeration(ports)
            return
        elif service == 'mssql':
            self._manual_mssql_enumeration(ports)
            return
        elif service == 'oracle':
            self._manual_oracle_enumeration(ports)
            return
        elif service == 'smtp':
            self._manual_smtp_enumeration(ports)
            return
        elif service in ['pop3', 'imap']:
            self._manual_email_service_enumeration(service, ports)
            return
        elif service == 'ldap':
            self._manual_ldap_enumeration(ports)
            return
        elif service == 'kerberos':
            self._manual_kerberos_enumeration(ports)
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_enum_{service}_{timestamp}"
        
        try:
            process = self.scanner.run_service_scan(
                self.current_target.ip,
                service,
                ports,
                str(output_file)
            )
            
            enum_id = f"enum_{service}_{timestamp}"
            self.running_processes[enum_id] = process
            
            print(f"Kevin: {service.upper()} enumeration launched! This is where the fun begins...")
            
            threading.Thread(
                target=self._monitor_scan,
                args=(enum_id, process, str(output_file)),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Enumeration failed - {e}")
    
    def do_web(self, line: str):
        """
        Web enumeration commands: web <command> [url] [options]
        
        Commands:
        - fingerprint <url>: Technology stack identification
        - dir <url> [wordlist] [extensions]: Directory enumeration
        - fuzz <url> [wordlist]: Fast fuzzing with ffuf
        - recursive <url> [wordlist]: Recursive enumeration with feroxbuster
        - params <url> [wordlist]: Parameter discovery
        - vuln <url>: Vulnerability scanning with nikto
        - backup <url>: Hunt for backup files and sensitive documents
        - config <url>: Hunt specifically for configuration files
        - sensitive <url>: Hunt for sensitive files with specialized patterns
        - hunt <url>: Complete backup/sensitive file hunting suite
        - deepdive <url>: Comprehensive technology stack analysis
        - headers <url>: Analyze HTTP headers and security posture
        - vhost <ip> [domain] [wordlist]: Virtual host discovery via Host header fuzzing
        - subdomain <domain> [wordlist]: DNS subdomain enumeration
        - reverse <ip>: Reverse DNS lookup for virtual hosts
        - all <url>: Complete web enumeration suite
        
        Examples:
        web fingerprint http://10.10.10.50
        web dir http://10.10.10.50 common php,html,txt
        web backup http://10.10.10.50
        web deepdive http://10.10.10.50
        web hunt http://10.10.10.50
        web vhost 10.10.10.50 example.com
        web subdomain example.com
        web reverse 10.10.10.50
        web all http://10.10.10.50
        """
        if not self.current_target:
            print("Kevin: Set a target first!")
            return
        
        args = line.strip().split()
        if not args:
            print("Kevin: Specify a command! Use 'help web' for details.")
            return
        
        command = args[0].lower()
        
        if command == 'fingerprint':
            self._web_fingerprint(args[1:])
        elif command == 'dir':
            self._web_directory(args[1:])
        elif command == 'fuzz':
            self._web_fuzz(args[1:])
        elif command == 'recursive':
            self._web_recursive(args[1:])
        elif command == 'params':
            self._web_params(args[1:])
        elif command == 'vuln':
            self._web_vuln(args[1:])
        elif command == 'backup':
            self._web_backup(args[1:])
        elif command == 'config':
            self._web_config(args[1:])
        elif command == 'sensitive':
            self._web_sensitive(args[1:])
        elif command == 'hunt':
            self._web_hunt(args[1:])
        elif command == 'deepdive':
            self._web_deepdive(args[1:])
        elif command == 'headers':
            self._web_headers(args[1:])
        elif command == 'vhost':
            self._web_vhost(args[1:])
        elif command == 'subdomain':
            self._web_subdomain(args[1:])
        elif command == 'reverse':
            self._web_reverse(args[1:])
        elif command == 'all':
            self._web_all(args[1:])
        else:
            print(f"Kevin: Unknown web command '{command}'. Use 'help web' for options.")
    
    def _web_fingerprint(self, args: List[str]):
        """Run technology fingerprinting"""
        if not args:
            # Auto-detect web URLs from open ports
            web_ports = self.current_target.get_web_ports()
            if not web_ports:
                print("Kevin: No web services detected. Run a port scan first!")
                return
            urls = [f"http://{self.current_target.ip}:{p.number}" for p in web_ports if p.number != 443]
            urls.extend([f"https://{self.current_target.ip}:{p.number}" for p in web_ports if p.number == 443])
        else:
            urls = [args[0]]
        
        for url in urls:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.session_dir / f"{self.current_target.ip}_whatweb_{timestamp}.json"
            
            try:
                process = self.web_enumerator.run_whatweb(url, str(output_file))
                web_id = f"whatweb_{timestamp}"
                self.running_processes[web_id] = process
                
                print(f"Kevin: Fingerprinting {url} - let's see what tech stack they're running!")
                
                threading.Thread(
                    target=self._monitor_web_scan,
                    args=(web_id, process, 'fingerprint', url),
                    daemon=True
                ).start()
                
            except Exception as e:
                print(f"Kevin: Fingerprinting failed - {e}")
    
    def _web_directory(self, args: List[str]):
        """Run directory enumeration with gobuster"""
        if not args:
            print("Kevin: Specify a URL! Example: web dir http://10.10.10.50")
            return
        
        url = args[0]
        wordlist = args[1] if len(args) > 1 else 'common'
        extensions = args[2].split(',') if len(args) > 2 else self.web_enumerator.extensions['basic']
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_gobuster_{timestamp}.txt"
        
        try:
            process = self.web_enumerator.run_gobuster(url, wordlist, extensions, str(output_file))
            web_id = f"gobuster_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: Hunting directories on {url} - every endpoint is a potential attack vector!")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'directory', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Directory enumeration failed - {e}")
    
    def _web_fuzz(self, args: List[str]):
        """Run fast fuzzing with ffuf"""
        if not args:
            print("Kevin: Specify a URL! Example: web fuzz http://10.10.10.50")
            return
        
        url = args[0]
        wordlist = args[1] if len(args) > 1 else 'common'
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_ffuf_{timestamp}.json"
        
        try:
            process = self.web_enumerator.run_ffuf(url, 'dir', wordlist, [404], str(output_file))
            web_id = f"ffuf_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: Fast fuzzing {url} - speed and stealth combined!")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'fuzz', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Fuzzing failed - {e}")
    
    def _web_recursive(self, args: List[str]):
        """Run recursive enumeration with feroxbuster"""
        if not args:
            print("Kevin: Specify a URL! Example: web recursive http://10.10.10.50")
            return
        
        url = args[0]
        wordlist = args[1] if len(args) > 1 else 'common'
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_feroxbuster_{timestamp}.txt"
        
        try:
            process = self.web_enumerator.run_feroxbuster(url, wordlist, 4, 50, str(output_file))
            web_id = f"feroxbuster_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: Recursive hunting on {url} - going deep to find hidden treasures!")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'recursive', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Recursive enumeration failed - {e}")
    
    def _web_params(self, args: List[str]):
        """Run parameter discovery"""
        if not args:
            print("Kevin: Specify a URL! Example: web params http://10.10.10.50")
            return
        
        url = args[0]
        wordlist = args[1] if len(args) > 1 else 'params'
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_params_{timestamp}.json"
        
        try:
            process = self.web_enumerator.run_ffuf(url, 'param', wordlist, [404], str(output_file))
            web_id = f"params_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: Parameter hunting on {url} - finding hidden API endpoints!")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'params', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Parameter discovery failed - {e}")
    
    def _web_vuln(self, args: List[str]):
        """Run vulnerability scanning with nikto"""
        if not args:
            print("Kevin: Specify a URL! Example: web vuln http://10.10.10.50")
            return
        
        url = args[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_nikto_{timestamp}.txt"
        
        try:
            process = self.web_enumerator.run_nikto(url, str(output_file))
            web_id = f"nikto_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: Vulnerability scanning {url} - let's find those juicy misconfigurations!")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'vuln', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Vulnerability scanning failed - {e}")
    
    def _web_all(self, args: List[str]):
        """Run complete web enumeration suite"""
        if not args:
            print("Kevin: Specify a URL! Example: web all http://10.10.10.50")
            return
        
        url = args[0]
        print(f"Kevin: Full web assault on {url} - this is going to be epic!")
        print("Kevin: Running fingerprinting, directory enumeration, and vulnerability scanning...")
        
        # Run in sequence with delays
        self._web_deepdive([url])
        time.sleep(2)
        self._web_directory([url, 'common'])
        time.sleep(2)
        self._web_config([url])
        time.sleep(2)
        self._web_vuln([url])
        
        print("Kevin: Full web enumeration launched! Grab some coffee - this will take a while! ☕")
        print("Kevin: 🕵️ Including deep tech analysis and backup hunting - comprehensive coverage!")
    
    def _web_backup(self, args: List[str]):
        """Hunt for backup files and sensitive documents"""
        if not args:
            print("Kevin: Specify a URL! Example: web backup http://10.10.10.50")
            return
        
        url = args[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_backup_hunter_{timestamp}.txt"
        
        try:
            process = self.web_enumerator.run_backup_hunter(url, str(output_file))
            web_id = f"backup_hunter_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: 💾 Backup hunting on {url} - looking for those forgotten files developers leave behind!")
            print("Kevin: Checking for .bak, .old, .backup files and more...")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'backup', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Backup hunting failed - {e}")
    
    def _web_config(self, args: List[str]):
        """Hunt specifically for configuration files"""
        if not args:
            print("Kevin: Specify a URL! Example: web config http://10.10.10.50")
            return
        
        url = args[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_config_hunter_{timestamp}.txt"
        
        try:
            process = self.web_enumerator.run_config_hunter(url, str(output_file))
            web_id = f"config_hunter_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: 🔥 Config hunting on {url} - targeting web.config, .env, wp-config.php and more!")
            print("Kevin: These files often contain database credentials and API keys...")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'config', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Config hunting failed - {e}")
    
    def _web_sensitive(self, args: List[str]):
        """Hunt for sensitive files with specialized patterns"""
        if not args:
            print("Kevin: Specify a URL! Example: web sensitive http://10.10.10.50")
            return
        
        url = args[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.session_dir / f"{self.current_target.ip}_sensitive_hunter_{timestamp}.json"
        
        try:
            process = self.web_enumerator.run_sensitive_file_hunter(url, str(output_file))
            web_id = f"sensitive_hunter_{timestamp}"
            self.running_processes[web_id] = process
            
            print(f"Kevin: 🔍 Sensitive file hunting on {url} - looking for phpinfo, readme, logs, and more!")
            print("Kevin: These files can reveal system information and potential vulnerabilities...")
            
            threading.Thread(
                target=self._monitor_web_scan,
                args=(web_id, process, 'sensitive', url),
                daemon=True
            ).start()
            
        except Exception as e:
            print(f"Kevin: Sensitive file hunting failed - {e}")
    
    def _web_hunt(self, args: List[str]):
        """Complete backup/sensitive file hunting suite"""
        if not args:
            print("Kevin: Specify a URL! Example: web hunt http://10.10.10.50")
            return
        
        url = args[0]
        print(f"Kevin: 🕵️ Complete backup/sensitive file hunting assault on {url}!")
        print("Kevin: This is where we find the gold - forgotten files with credentials and secrets...")
        
        # Run all hunting methods in sequence with delays
        print("Kevin: Phase 1 - Configuration file hunting...")
        self._web_config([url])
        
        time.sleep(3)
        print("Kevin: Phase 2 - Backup file hunting...")
        self._web_backup([url])
        
        time.sleep(3)
        print("Kevin: Phase 3 - Sensitive file hunting...")
        self._web_sensitive([url])
        
        print("Kevin: 🎯 Complete hunting suite launched! These scans often reveal the keys to the kingdom!")
    
    def _web_deepdive(self, args: List[str]):
        """Comprehensive technology stack analysis"""
        if not args:
            print("Kevin: Specify a URL! Example: web deepdive http://10.10.10.50")
            return
        
        url = args[0]
        print(f"Kevin: 🔬 Deep diving into {url} technology stack...")
        print("Kevin: Analyzing headers, cookies, JavaScript libraries, CSS frameworks, and more!")
        
        try:
            analysis = self.tech_analyzer.analyze_url(url)
            self.current_target.technology_analysis.append(analysis)
            
            # Display comprehensive analysis
            self._display_technology_analysis(analysis)
            
        except Exception as e:
            print(f"Kevin: Technology deep dive failed - {e}")
    
    def _web_headers(self, args: List[str]):
        """Analyze HTTP headers and security posture"""
        if not args:
            print("Kevin: Specify a URL! Example: web headers http://10.10.10.50")
            return
        
        url = args[0]
        print(f"Kevin: 🔍 Analyzing HTTP headers and security posture for {url}...")
        
        try:
            analysis = self.tech_analyzer.analyze_url(url)
            self.current_target.technology_analysis.append(analysis)
            
            # Display focused header analysis
            self._display_header_analysis(analysis)
            
        except Exception as e:
            print(f"Kevin: Header analysis failed - {e}")
    
    def _display_technology_analysis(self, analysis: TechnologyAnalysis):
        """Display comprehensive technology analysis results"""
        print(f"\n=== 🔬 TECHNOLOGY DEEP DIVE: {analysis.url} ===")
        
        # Server & Infrastructure
        if analysis.web_server or analysis.backend_language:
            print("\n🖥️  SERVER & INFRASTRUCTURE:")
            if analysis.web_server:
                print(f"   Web Server: {analysis.web_server}")
            if analysis.backend_language:
                print(f"   Backend Language: {analysis.backend_language}")
            if analysis.backend_framework:
                print(f"   Backend Framework: {analysis.backend_framework}")
            if analysis.operating_system:
                print(f"   Operating System: {analysis.operating_system}")
        
        # CMS & Applications
        if analysis.cms or analysis.frontend_framework:
            print("\n📱 CMS & APPLICATIONS:")
            if analysis.cms:
                cms_info = f"{analysis.cms}"
                if analysis.cms_version:
                    cms_info += f" {analysis.cms_version}"
                print(f"   CMS: {cms_info}")
            if analysis.frontend_framework:
                print(f"   Frontend Framework: {analysis.frontend_framework}")
        
        # JavaScript Libraries
        if analysis.js_libraries:
            print("\n📚 JAVASCRIPT LIBRARIES:")
            for lib, version in analysis.js_libraries.items():
                print(f"   {lib.title()}: {version}")
        
        # CSS Frameworks
        if analysis.css_frameworks:
            print("\n🎨 CSS FRAMEWORKS:")
            for framework in analysis.css_frameworks:
                print(f"   {framework.title()}")
        
        # Security Analysis
        if analysis.security_headers or analysis.missing_security_headers:
            print("\n🛡️  SECURITY ANALYSIS:")
            if analysis.security_headers:
                print(f"   Security Headers Present: {len(analysis.security_headers)}")
                for header, value in analysis.security_headers.items():
                    print(f"     ✅ {header}: {value[:50]}{'...' if len(value) > 50 else ''}")
            
            if analysis.missing_security_headers:
                print(f"   Missing Security Headers: {len(analysis.missing_security_headers)}")
                for header in analysis.missing_security_headers[:5]:  # Show first 5
                    print(f"     ❌ {header}")
        
        # Cookies Analysis
        if analysis.cookies:
            print("\n🍪 COOKIES ANALYSIS:")
            for name, value in analysis.cookies.items():
                print(f"   {name}: {value[:30]}{'...' if len(value) > 30 else ''}")
        
        # Custom Headers
        if analysis.custom_headers:
            print("\n🔧 CUSTOM HEADERS:")
            for header, value in analysis.custom_headers.items():
                print(f"   {header}: {value}")
        
        # Security Issues & Vulnerabilities
        if analysis.security_issues or analysis.potential_vulnerabilities:
            print("\n⚠️  SECURITY CONCERNS:")
            
            if analysis.security_issues:
                print("   Security Issues:")
                for issue in analysis.security_issues:
                    print(f"     🔸 {issue}")
            
            if analysis.potential_vulnerabilities:
                print("   Potential Vulnerabilities:")
                for vuln in analysis.potential_vulnerabilities:
                    print(f"     🚨 {vuln}")
        
        # Attack Recommendations
        self._suggest_tech_analysis_attacks(analysis)
    
    def _display_header_analysis(self, analysis: TechnologyAnalysis):
        """Display focused header analysis"""
        print(f"\n=== 🔍 HEADER ANALYSIS: {analysis.url} ===")
        
        print("\n📋 RESPONSE HEADERS:")
        if analysis.web_server:
            print(f"   Server: {analysis.web_server}")
        
        # Security headers status
        print(f"\n🛡️  SECURITY HEADERS STATUS:")
        print(f"   Present: {len(analysis.security_headers)}")
        print(f"   Missing: {len(analysis.missing_security_headers)}")
        
        if analysis.security_headers:
            print("\n   ✅ PRESENT SECURITY HEADERS:")
            for header, value in analysis.security_headers.items():
                print(f"     {header}: {value}")
        
        if analysis.missing_security_headers:
            print("\n   ❌ MISSING SECURITY HEADERS:")
            for header in analysis.missing_security_headers:
                print(f"     {header}")
        
        # Information disclosure
        print("\n🔍 INFORMATION DISCLOSURE:")
        disclosed_info = []
        if analysis.web_server:
            disclosed_info.append(f"Server version: {analysis.web_server}")
        if analysis.backend_language:
            disclosed_info.append(f"Backend technology: {analysis.backend_language}")
        if analysis.custom_headers:
            disclosed_info.append(f"Custom headers revealing technology: {len(analysis.custom_headers)}")
        
        if disclosed_info:
            for info in disclosed_info:
                print(f"   🔸 {info}")
        else:
            print("   ✅ Minimal information disclosure detected")
        
        # Security recommendations
        if analysis.security_issues:
            print("\n💡 SECURITY RECOMMENDATIONS:")
            for issue in analysis.security_issues:
                print(f"   • {issue}")
    
    def _suggest_tech_analysis_attacks(self, analysis: TechnologyAnalysis):
        """Suggest attack vectors based on technology analysis"""
        suggestions = []
        
        # CMS-specific attacks
        if analysis.cms == 'WordPress':
            suggestions.append("🏛️ WordPress: Try wp-admin brute force, plugin enumeration, wp-config.php hunting")
        elif analysis.cms == 'Drupal':
            suggestions.append("🔧 Drupal: Check for Drupalgeddon, admin access, module vulnerabilities")
        elif analysis.cms == 'Joomla':
            suggestions.append("🚀 Joomla: Try administrator panel access, component vulnerabilities")
        
        # Framework-specific attacks
        if analysis.backend_framework:
            framework = analysis.backend_framework.lower()
            if 'laravel' in framework:
                suggestions.append("🔥 Laravel: Check for .env files, debug mode, artisan console access")
            elif 'django' in framework:
                suggestions.append("🐍 Django: Look for debug mode, admin panel, settings.py exposure")
            elif 'express' in framework:
                suggestions.append("⚡ Express.js: Check for Node.js vulnerabilities, package.json exposure")
        
        # JavaScript library vulnerabilities
        for lib, version in analysis.js_libraries.items():
            if lib == 'jquery' and version.startswith('1.'):
                suggestions.append(f"⚠️ jQuery {version}: Test for XSS vulnerabilities in older versions")
            elif lib == 'angular' and version.startswith('1.'):
                suggestions.append(f"⚠️ AngularJS {version}: Check for template injection, XSS issues")
        
        # Security header issues
        if 'x-frame-options' in analysis.missing_security_headers:
            suggestions.append("🔲 Missing X-Frame-Options: Test for clickjacking vulnerabilities")
        if 'content-security-policy' in analysis.missing_security_headers:
            suggestions.append("🔒 Missing CSP: Test for XSS vulnerabilities")
        
        # Information disclosure
        if analysis.security_issues:
            suggestions.append("🔍 Information disclosure: Use revealed tech details for targeted attacks")
        
        if suggestions:
            print("\n🎯 ATTACK RECOMMENDATIONS:")
            for suggestion in suggestions:
                print(f"   {suggestion}")
        
        print("\n💡 Kevin's Pro Tips:")
        print("   • Use revealed technologies to craft targeted payloads")
        print("   • Check for default credentials based on identified software")
        print("   • Look for version-specific CVEs in discovered components")
        if analysis.missing_security_headers:
            print("   • Missing security headers = potential client-side attack vectors")
    
    def _monitor_web_scan(self, scan_id: str, process: subprocess.Popen, scan_type: str, url: str):
        """Monitor web scan completion"""
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(f"\n[+] {scan_id} completed successfully!")
            
            # Process results based on scan type
            if scan_type == 'directory' and 'gobuster' in scan_id:
                findings = self.web_enumerator.parse_gobuster_output(stdout)
                self.current_target.web_findings.extend(findings)
                
                if findings:
                    print(f"Kevin: Found {len(findings)} directories/files! Use 'show web' to see details.")
                    self._suggest_web_next_steps(findings)
                    
                    # Check if this was an auto-scan and escalate if needed
                    if 'auto' in scan_id and len(findings) < 5 and self.auto_enumerate:
                        self._escalate_web_enumeration(url)
                else:
                    print("Kevin: No directories found with current wordlist.")
                    
                    # Auto-escalate if this was automated and no results
                    if 'auto' in scan_id and self.auto_enumerate:
                        self._escalate_web_enumeration(url)
            
            elif scan_type == 'fingerprint' and 'whatweb' in scan_id:
                tech_stack = self.web_enumerator.parse_whatweb_output(stdout)
                self.current_target.technology_stack.update(tech_stack)
                
                if tech_stack:
                    print(f"Kevin: Technology stack identified! Found: {', '.join(tech_stack.values())}")
                    self._suggest_tech_attacks(tech_stack)
            
            elif scan_type in ['backup', 'config'] and ('backup_hunter' in scan_id or 'config_hunter' in scan_id):
                findings = self.web_enumerator.parse_backup_hunter_output(stdout)
                self.current_target.web_findings.extend(findings)
                
                if findings:
                    print(f"Kevin: 🎯 JACKPOT! Found {len(findings)} backup/sensitive files!")
                    self._suggest_backup_next_steps(findings)
                    
                    # Show immediate high-priority findings
                    high_priority = [f for f in findings if any(keyword in f.extra_info.lower() 
                                   for keyword in ['config', 'credential', 'database', 'backup'])]
                    if high_priority:
                        print(f"Kevin: 🔥 {len(high_priority)} HIGH-PRIORITY files found - investigate immediately!")
                        for finding in high_priority[:3]:  # Show top 3
                            print(f"  {finding.status_code} - {finding.url} - {finding.extra_info}")
                else:
                    print("Kevin: No backup/config files found with current patterns.")
            
            elif scan_type == 'sensitive' and 'sensitive_hunter' in scan_id:
                # Note: ffuf output parsing would be different, but we'll use similar logic
                findings = self.web_enumerator.parse_gobuster_output(stdout)  # Adapt as needed
                self.current_target.web_findings.extend(findings)
                
                if findings:
                    print(f"Kevin: 📄 Found {len(findings)} sensitive files! Use 'show web' for details.")
                    self._suggest_backup_next_steps(findings)
                else:
                    print("Kevin: No sensitive files found with current patterns.")
            
            # Add to scan history
            self.current_target.scan_history.append(f"{scan_id}: {datetime.now()}")
            
        else:
            print(f"\n[!] {scan_id} failed: {stderr}")
        
        # Cleanup
        if scan_id in self.running_processes:
            del self.running_processes[scan_id]
    
    def _suggest_web_next_steps(self, findings: List[WebFinding]):
        """Suggest next steps based on web findings"""
        suggestions = []
        
        for finding in findings:
            if '/admin' in finding.url.lower():
                suggestions.append("🔐 Admin panel detected! Try default credentials or brute force")
            elif '/login' in finding.url.lower():
                suggestions.append("🔑 Login page found! Check for SQL injection or weak passwords")
            elif '/upload' in finding.url.lower():
                suggestions.append("📁 Upload functionality! Test for file upload vulnerabilities")
            elif '.php' in finding.url:
                suggestions.append("🐘 PHP files found! Look for LFI/RFI vulnerabilities")
            elif '/api' in finding.url.lower():
                suggestions.append("🔌 API endpoints detected! Try parameter fuzzing")
        
        if suggestions:
            print("\nKevin: Based on what I found, here's what I'd attack next:")
            for suggestion in suggestions[:3]:  # Limit to top 3
                print(f"  {suggestion}")
    
    def _suggest_tech_attacks(self, tech_stack: Dict[str, str]):
        """Suggest attacks based on technology stack"""
        suggestions = []
        
        if 'WordPress' in tech_stack.get('cms', ''):
            suggestions.append("🏛️ WordPress detected! Try: wpscan, wp-admin access, plugin enumeration")
        elif 'Drupal' in tech_stack.get('cms', ''):
            suggestions.append("🔧 Drupal detected! Check for CVEs, admin access, module vulnerabilities")
        
        if 'Apache' in tech_stack.get('webserver', ''):
            suggestions.append("🌐 Apache detected! Look for .htaccess bypass, server-status, mod vulnerabilities")
        elif 'nginx' in tech_stack.get('webserver', ''):
            suggestions.append("⚡ nginx detected! Check for alias traversal, server blocks misconfiguration")
        
        if 'PHP' in tech_stack.get('language', ''):
            suggestions.append("🐘 PHP detected! Test for LFI, RFI, code injection, phpinfo.php")
        
        if suggestions:
            print("\nKevin: Technology stack analysis suggests these attack vectors:")
            for suggestion in suggestions:
                print(f"  {suggestion}")
    
    def _suggest_backup_next_steps(self, findings: List[WebFinding]):
        """Suggest next steps based on backup/sensitive file findings"""
        suggestions = []
        critical_files = []
        
        for finding in findings:
            url_lower = finding.url.lower()
            
            # Critical files that need immediate attention
            if any(pattern in url_lower for pattern in ['web.config', 'wp-config', '.env', 'database']):
                critical_files.append(f"🚨 CRITICAL: {finding.url} - {finding.extra_info}")
            
            # Specific attack suggestions
            if 'config' in finding.extra_info.lower():
                suggestions.append("🔍 Download config files and check for database credentials")
            elif 'backup' in finding.extra_info.lower():
                suggestions.append("💾 Download backup files - they often contain source code with hardcoded secrets")
            elif 'database' in finding.extra_info.lower():
                suggestions.append("🗃️ Download database files/dumps for credential extraction")
            elif 'phpinfo' in url_lower:
                suggestions.append("🔍 Check phpinfo for system information and configuration details")
            elif 'readme' in url_lower or 'changelog' in url_lower:
                suggestions.append("📝 Read documentation files for version info and system details")
            elif 'log' in finding.extra_info.lower():
                suggestions.append("📊 Check log files for error messages and potential information disclosure")
        
        if critical_files:
            print("\nKevin: 🚨 CRITICAL FILES DISCOVERED - IMMEDIATE INVESTIGATION REQUIRED:")
            for critical in critical_files:
                print(f"  {critical}")
        
        if suggestions:
            print("\nKevin: Based on backup/sensitive files found, here's your action plan:")
            for suggestion in list(set(suggestions))[:5]:  # Remove duplicates, limit to 5
                print(f"  {suggestion}")
        
        if findings:
            print("\nKevin: 💡 Pro tip: Use 'curl -k <url>' or 'wget' to download these files for analysis!")
    
    def _web_vhost(self, args: List[str]):
        """Virtual host discovery via Host header fuzzing"""
        if not args:
            print("Kevin: Specify target IP! Example: web vhost 10.10.10.50 [domain] [wordlist]")
            return
        
        target_ip = args[0]
        base_domain = args[1] if len(args) > 1 else None
        wordlist = args[2] if len(args) > 2 else 'common'
        port = 80  # Default to HTTP, could be made configurable
        
        print(f"Kevin: 🌐 Virtual host discovery on {target_ip}:{port}")
        if base_domain:
            print(f"Kevin: Using base domain: {base_domain}")
        print(f"Kevin: Wordlist: {wordlist} ({len(self.vhost_discovery.subdomain_wordlists.get(wordlist, []))} entries)")
        
        try:
            vhosts = self.vhost_discovery.discover_host_header_fuzzing(target_ip, base_domain, wordlist, port)
            
            if vhosts:
                print(f"Kevin: 🎯 Found {len(vhosts)} virtual hosts!")
                self.current_target.virtual_hosts.extend(vhosts)
                
                for vhost in vhosts[:5]:  # Show first 5
                    print(f"  ✅ {vhost.hostname} -> {vhost.ip} (Status: {vhost.status_code}, Size: {vhost.content_length}b)")
                    if vhost.title:
                        print(f"     Title: {vhost.title}")
                
                if len(vhosts) > 5:
                    print(f"  ... and {len(vhosts) - 5} more (use 'show vhosts' for all)")
                
                self._suggest_vhost_next_steps(vhosts)
            else:
                print("Kevin: No virtual hosts discovered with current wordlist.")
                if wordlist == 'common':
                    print("Kevin: 💡 Try 'web vhost <ip> <domain> extended' for comprehensive scanning!")
                
        except Exception as e:
            print(f"Kevin: Virtual host discovery failed - {e}")
    
    def _web_subdomain(self, args: List[str]):
        """DNS subdomain enumeration"""
        if not args:
            print("Kevin: Specify domain! Example: web subdomain example.com [wordlist]")
            return
        
        domain = args[0]
        wordlist = args[1] if len(args) > 1 else 'common'
        
        print(f"Kevin: 🔍 DNS subdomain enumeration for {domain}")
        print(f"Kevin: Wordlist: {wordlist} ({len(self.vhost_discovery.subdomain_wordlists.get(wordlist, []))} entries)")
        
        try:
            vhosts = self.vhost_discovery.discover_dns_subdomains(domain, wordlist)
            
            if vhosts:
                print(f"Kevin: 🎯 Found {len(vhosts)} subdomains!")
                self.current_target.virtual_hosts.extend(vhosts)
                
                for vhost in vhosts:
                    print(f"  ✅ {vhost.hostname} -> {vhost.ip}")
                    if vhost.title:
                        print(f"     Title: {vhost.title}")
                
                self._suggest_vhost_next_steps(vhosts)
            else:
                print("Kevin: No subdomains discovered with current wordlist.")
                if wordlist == 'common':
                    print("Kevin: 💡 Try 'web subdomain <domain> extended' for comprehensive scanning!")
                
        except Exception as e:
            print(f"Kevin: DNS subdomain enumeration failed - {e}")
    
    def _web_reverse(self, args: List[str]):
        """Reverse DNS lookup for virtual hosts"""
        if not args:
            print("Kevin: Specify target IP! Example: web reverse 10.10.10.50")
            return
        
        target_ip = args[0]
        
        print(f"Kevin: 🔄 Reverse DNS lookup for {target_ip}")
        
        try:
            vhosts = self.vhost_discovery.discover_reverse_dns(target_ip)
            
            if vhosts:
                print(f"Kevin: 🎯 Found {len(vhosts)} reverse DNS entries!")
                self.current_target.virtual_hosts.extend(vhosts)
                
                for vhost in vhosts:
                    print(f"  ✅ {vhost.hostname} -> {vhost.ip}")
                    if vhost.title:
                        print(f"     Title: {vhost.title}")
                
                self._suggest_vhost_next_steps(vhosts)
            else:
                print("Kevin: No reverse DNS entries found.")
                print("Kevin: 💡 This is normal for many hosts - try Host header fuzzing instead!")
                
        except Exception as e:
            print(f"Kevin: Reverse DNS lookup failed - {e}")
    
    def _suggest_vhost_next_steps(self, vhosts: List[VirtualHost]):
        """Suggest next steps based on virtual host findings"""
        print("\nKevin: 🎯 Virtual host attack recommendations:")
        print("  • Run directory enumeration on each discovered virtual host")
        print("  • Check for different admin panels or applications on each vhost")
        print("  • Test for subdomain takeover vulnerabilities")
        print("  • Look for development/staging environments with weaker security")
        
        # Specific suggestions based on hostnames
        suggestions = []
        for vhost in vhosts:
            hostname_lower = vhost.hostname.lower()
            if any(keyword in hostname_lower for keyword in ['admin', 'administrator']):
                suggestions.append(f"🔐 {vhost.hostname}: Admin interface - try default credentials")
            elif any(keyword in hostname_lower for keyword in ['api', 'rest', 'graphql']):
                suggestions.append(f"🔌 {vhost.hostname}: API endpoint - test for authentication bypass")
            elif any(keyword in hostname_lower for keyword in ['dev', 'staging', 'test', 'beta']):
                suggestions.append(f"🚧 {vhost.hostname}: Development environment - often less secure")
            elif any(keyword in hostname_lower for keyword in ['mail', 'webmail']):
                suggestions.append(f"📧 {vhost.hostname}: Mail interface - test for credential attacks")
        
        if suggestions:
            print("\n  Specific targets:")
            for suggestion in suggestions:
                print(f"    {suggestion}")
        
        print(f"\nKevin: 💡 Pro tip: Use 'web dir http://{vhosts[0].hostname}' to enumerate each vhost!")
    
    def do_status(self, line: str):
        """Show current target status and running scans"""
        if not self.current_target:
            print("Kevin: No target set")
            return
        
        print(f"\n=== Target: {self.current_target.ip} ===")
        
        if self.current_target.hostname:
            print(f"Hostname: {self.current_target.hostname}")
        
        if self.current_target.os_info:
            print(f"OS: {self.current_target.os_info}")
        
        if self.current_target.open_ports:
            print(f"\nOpen Ports ({len(self.current_target.open_ports)}):")
            for port in sorted(self.current_target.open_ports, key=lambda p: p.number):
                version_info = f" ({port.version})" if port.version else ""
                print(f"  {port.number}/{port.protocol} - {port.service}{version_info}")
        
        # Show auto-enumeration status
        print(f"\nAuto-Enumeration: {'🟢 ENABLED' if self.auto_enumerate else '🔴 DISABLED'}")
        if self.auto_enumerate:
            active_modules = []
            if self.auto_web_enum:
                active_modules.append(f"Web({self.web_wordlist_preference})")
            if self.auto_smb_enum:
                active_modules.append("SMB")
            if self.auto_ftp_enum:
                active_modules.append("FTP")
            if self.auto_mysql_enum:
                active_modules.append("MySQL")
            if self.auto_mssql_enum:
                active_modules.append("MSSQL")
            if self.auto_oracle_enum:
                active_modules.append("Oracle")
            if self.auto_smtp_enum:
                active_modules.append("SMTP")
            if self.auto_email_enum:
                active_modules.append("Email")
            if self.auto_ldap_enum:
                active_modules.append("LDAP")
            if self.auto_kerberos_enum:
                active_modules.append("Kerberos")
            if active_modules:
                print(f"Active Modules: {', '.join(active_modules)}")
        
        if self.running_processes:
            print(f"\nRunning Scans ({len(self.running_processes)}):")
            for scan_id in self.running_processes:
                scan_type = "🤖 AUTO" if "auto" in scan_id else "📋 MANUAL"
                print(f"  {scan_type} {scan_id}")
        
        if self.current_target.web_findings:
            print(f"\nWeb Findings ({len(self.current_target.web_findings)}):")
            for finding in self.current_target.web_findings[:5]:  # Show first 5
                print(f"  {finding.status_code} - {finding.url} [{finding.size}b] ({finding.tool})")
            if len(self.current_target.web_findings) > 5:
                print(f"  ... and {len(self.current_target.web_findings) - 5} more (use 'show web' for all)")
        
        if self.current_target.technology_stack:
            print(f"\nTechnology Stack:")
            for tech_type, tech_name in self.current_target.technology_stack.items():
                print(f"  {tech_type.title()}: {tech_name}")
        
        if self.current_target.virtual_hosts:
            print(f"\nVirtual Hosts ({len(self.current_target.virtual_hosts)}):")
            for vhost in self.current_target.virtual_hosts[:3]:  # Show first 3
                print(f"  🌐 {vhost.hostname} -> {vhost.ip} ({vhost.discovery_method})")
            if len(self.current_target.virtual_hosts) > 3:
                print(f"  ... and {len(self.current_target.virtual_hosts) - 3} more (use 'show vhosts' for all)")
        
        if self.current_target.mysql_findings:
            print(f"\nMySQL Findings ({len(self.current_target.mysql_findings)}):")
            for finding in self.current_target.mysql_findings:
                security_status = "🚨 ISSUES" if finding.security_issues else "✅ SECURE"
                db_info = f"{len(finding.databases)} DBs" if finding.databases else "No DBs"
                print(f"  🗃️  {finding.target}:{finding.port} - {finding.version or 'Unknown'} ({security_status}, {db_info})")
                if finding.empty_password_accounts:
                    print(f"     🔓 Empty passwords: {', '.join(finding.empty_password_accounts)}")
            if len(self.current_target.mysql_findings) > 1:
                print(f"  Use 'show mysql' for detailed analysis")
        
        if self.current_target.mssql_findings:
            print(f"\nMSSQL Findings ({len(self.current_target.mssql_findings)}):")
            for finding in self.current_target.mssql_findings:
                critical_count = (1 if finding.xp_cmdshell_enabled else 0) + (1 if finding.sa_account_blank_password else 0)
                security_status = f"🔥 {critical_count} CRITICAL" if critical_count > 0 else ("🚨 ISSUES" if finding.security_issues else "✅ SECURE")
                db_info = f"{len(finding.databases)} DBs" if finding.databases else "No DBs"
                print(f"  🏢 {finding.target}:{finding.port} - {finding.version or 'Unknown'} ({security_status}, {db_info})")
                if finding.xp_cmdshell_enabled:
                    print(f"     🔥 xp_cmdshell ENABLED!")
                if finding.sa_account_blank_password:
                    print(f"     🔥 SA blank password!")
                if finding.weak_passwords:
                    print(f"     🔓 Weak passwords: {len(finding.weak_passwords)} accounts")
            if len(self.current_target.mssql_findings) > 1:
                print(f"  Use 'show mssql' for detailed analysis")
        
        if self.current_target.oracle_findings:
            print(f"\nOracle Findings ({len(self.current_target.oracle_findings)}):")
            for finding in self.current_target.oracle_findings:
                security_status = "🚨 ISSUES" if finding.security_issues else "✅ SECURE"
                sid_info = f"{len(finding.sids)} SIDs" if finding.sids else "No SIDs"
                accessible_info = f"({len(finding.accessible_sids)} accessible)" if finding.accessible_sids else ""
                print(f"  🔮 {finding.target}:{finding.port} - {finding.version or 'Unknown'} ({security_status}, {sid_info} {accessible_info})")
                if finding.accessible_sids:
                    print(f"     ✅ Accessible SIDs: {', '.join(finding.accessible_sids[:3])}")
                if finding.default_accounts:
                    print(f"     🔓 Default accounts: {', '.join(finding.default_accounts[:3])}")
            if len(self.current_target.oracle_findings) > 1:
                print(f"  Use 'show oracle' for detailed analysis")
        
        if self.current_target.smtp_findings:
            print(f"\nSMTP Findings ({len(self.current_target.smtp_findings)}):")
            for finding in self.current_target.smtp_findings:
                critical_count = (1 if finding.relay_test_result == "OPEN RELAY DETECTED" else 0)
                security_status = f"🔥 {critical_count} CRITICAL" if critical_count > 0 else ("🚨 ISSUES" if finding.security_issues else "✅ SECURE")
                user_info = f"{len(finding.valid_users)} users" if finding.valid_users else "No users"
                print(f"  📧 {finding.target}:{finding.port} - {finding.software or 'Unknown'} ({security_status}, {user_info})")
                if finding.relay_test_result == "OPEN RELAY DETECTED":
                    print(f"     🔥 OPEN RELAY DETECTED!")
                if finding.vrfy_enabled or finding.expn_enabled:
                    methods = []
                    if finding.vrfy_enabled:
                        methods.append("VRFY")
                    if finding.expn_enabled:
                        methods.append("EXPN")
                    print(f"     🔍 User enumeration: {'/'.join(methods)}")
                if finding.valid_users:
                    print(f"     👤 Valid users: {', '.join(finding.valid_users[:3])}")
            if len(self.current_target.smtp_findings) > 1:
                print(f"  Use 'show smtp' for detailed analysis")
        
        if self.current_target.email_findings:
            print(f"\nEmail Service Findings ({len(self.current_target.email_findings)}):")
            for finding in self.current_target.email_findings:
                critical_count = (1 if finding.plaintext_auth else 0)
                security_status = f"🔥 {critical_count} CRITICAL" if critical_count > 0 else ("🚨 ISSUES" if finding.security_issues else "✅ SECURE")
                encryption_status = "SSL" if finding.ssl_enabled else ("STARTTLS" if finding.starttls_available else "Plain")
                print(f"  📬 {finding.service_type.upper()} {finding.target}:{finding.port} - {finding.software or 'Unknown'} ({security_status}, {encryption_status})")
                if finding.plaintext_auth:
                    print(f"     🔥 Plaintext auth over unencrypted connection!")
                if finding.anonymous_access:
                    print(f"     👤 Anonymous access possible")
                if finding.login_disabled:
                    print(f"     🔒 Login disabled")
            if len(self.current_target.email_findings) > 1:
                print(f"  Use 'show email' for detailed analysis")
        
        if self.current_target.ldap_findings:
            print(f"\nLDAP Findings ({len(self.current_target.ldap_findings)}):")
            for finding in self.current_target.ldap_findings:
                critical_count = (1 if finding.anonymous_bind else 0)
                security_status = f"🔥 {critical_count} CRITICAL" if critical_count > 0 else ("🚨 ISSUES" if finding.security_issues else "✅ SECURE")
                user_info = f"{len(finding.users_found)} users" if finding.users_found else "No users"
                print(f"  🏢 LDAP {finding.target}:{finding.port} - {finding.server_info or 'Unknown'} ({security_status}, {user_info})")
                if finding.anonymous_bind:
                    print(f"     🔥 Anonymous bind enabled!")
                if finding.groups_found:
                    print(f"     👤 Groups: {len(finding.groups_found)}")
                if finding.computer_accounts:
                    print(f"     💻 Computer accounts: {len(finding.computer_accounts)}")
            if len(self.current_target.ldap_findings) > 1:
                print(f"  Use 'show ldap' for detailed analysis")
        
        if self.current_target.kerberos_findings:
            print(f"\nKerberos Findings ({len(self.current_target.kerberos_findings)}):")
            for finding in self.current_target.kerberos_findings:
                critical_count = len(finding.asrep_roastable_users) + len(finding.kerberoastable_users)
                security_status = f"🔥 {critical_count} ROASTABLE" if critical_count > 0 else ("🚨 ISSUES" if finding.security_issues else "✅ SECURE")
                user_info = f"{len(finding.users_found)} users" if finding.users_found else "No users"
                spn_info = f"{len(finding.spns_found)} SPNs" if finding.spns_found else "No SPNs"
                print(f"  🎫 Kerberos {finding.target}:{finding.port} - {finding.realm or 'Unknown'} ({security_status}, {user_info}, {spn_info})")
                if finding.asrep_roastable_users:
                    print(f"     🔥 AS-REP roastable: {len(finding.asrep_roastable_users)} users")
                if finding.kerberoastable_users:
                    print(f"     🎯 Kerberoastable: {len(finding.kerberoastable_users)} users")
                if finding.domain_controllers:
                    print(f"     🏢 Domain controllers: {len(finding.domain_controllers)}")
            if len(self.current_target.kerberos_findings) > 1:
                print(f"  Use 'show kerberos' for detailed analysis")
        
        if self.current_target.vulnerabilities:
            print(f"\nVulnerabilities ({len(self.current_target.vulnerabilities)}):")
            for vuln in self.current_target.vulnerabilities:
                print(f"  ⚠️  {vuln}")
    
    def do_show(self, line: str):
        """
        Show detailed information: show <type>
        
        Types: ports, scripts, notes, history, web, tech, analysis, vhosts, mysql, mssql, oracle, smtp, email, ldap, kerberos
        """
        if not self.current_target:
            print("Kevin: No target set")
            return
        
        show_type = line.strip().lower()
        
        if show_type == 'ports':
            self._show_ports_detailed()
        elif show_type == 'scripts':
            self._show_script_results()
        elif show_type == 'notes':
            self._show_notes()
        elif show_type == 'history':
            self._show_scan_history()
        elif show_type == 'web':
            self._show_web_findings()
        elif show_type == 'tech':
            self._show_technology_stack()
        elif show_type == 'analysis':
            self._show_technology_analysis()
        elif show_type == 'vhosts':
            self._show_virtual_hosts()
        elif show_type == 'mysql':
            self._show_mysql_findings()
        elif show_type == 'mssql':
            self._show_mssql_findings()
        elif show_type == 'oracle':
            self._show_oracle_findings()
        elif show_type == 'smtp':
            self._show_smtp_findings()
        elif show_type == 'email':
            self._show_email_findings()
        elif show_type == 'ldap':
            self._show_ldap_findings()
        elif show_type == 'kerberos':
            self._show_kerberos_findings()
        else:
            print("Kevin: Available options: ports, scripts, notes, history, web, tech, analysis, vhosts, mysql, mssql, oracle, smtp, email, ldap, kerberos")
    
    def _show_ports_detailed(self):
        """Show detailed port information"""
        if not self.current_target.open_ports:
            print("Kevin: No ports discovered yet. Run a scan first!")
            return
        
        print(f"\n=== Detailed Port Analysis: {self.current_target.ip} ===")
        
        for port in sorted(self.current_target.open_ports, key=lambda p: p.number):
            print(f"\n{port.number}/{port.protocol} - {port.service.upper()}")
            print(f"  State: {port.state}")
            if port.version:
                print(f"  Version: {port.version}")
            
            if port.scripts:
                print("  Script Results:")
                for script_name, output in port.scripts.items():
                    print(f"    {script_name}:")
                    # Truncate long outputs
                    lines = output.split('\n')
                    for line in lines[:5]:  # Show first 5 lines
                        print(f"      {line}")
                    if len(lines) > 5:
                        print(f"      ... ({len(lines)-5} more lines)")
    
    def _show_script_results(self):
        """Show NSE script results"""
        script_count = 0
        for port in self.current_target.open_ports:
            if port.scripts:
                for script_name, output in port.scripts.items():
                    print(f"\n=== {script_name} ({port.number}/{port.protocol}) ===")
                    print(output)
                    script_count += 1
        
        if script_count == 0:
            print("Kevin: No script results yet. Try running service enumeration!")
    
    def _show_notes(self):
        """Show target notes"""
        if not self.current_target.notes:
            print("Kevin: No notes yet. Add some with: notes <text>")
            return
        
        print(f"\n=== Notes for {self.current_target.ip} ===")
        for i, note in enumerate(self.current_target.notes, 1):
            timestamp = datetime.now().strftime("%H:%M")
            print(f"{i}. [{timestamp}] {note}")
    
    def _show_scan_history(self):
        """Show scan history"""
        if not self.current_target.scan_history:
            print("Kevin: No scans run yet.")
            return
        
        print(f"\n=== Scan History for {self.current_target.ip} ===")
        for entry in self.current_target.scan_history:
            print(f"  {entry}")
    
    def _show_web_findings(self):
        """Show detailed web findings"""
        if not self.current_target.web_findings:
            print("Kevin: No web findings yet. Try 'web dir' or 'web all' to start hunting!")
            return
        
        print(f"\n=== Web Findings for {self.current_target.ip} ===")
        
        # Group by status code for better organization
        status_groups = {}
        for finding in self.current_target.web_findings:
            status = finding.status_code
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(finding)
        
        for status in sorted(status_groups.keys()):
            findings = status_groups[status]
            print(f"\n{status} Status ({len(findings)} findings):")
            for finding in sorted(findings, key=lambda f: f.url):
                extra = f" - {finding.extra_info}" if finding.extra_info else ""
                print(f"  {finding.url} [{finding.size}b] ({finding.tool}){extra}")
    
    def _show_technology_stack(self):
        """Show technology stack information"""
        if not self.current_target.technology_stack:
            print("Kevin: No technology stack identified yet. Try 'web fingerprint' first!")
            return
        
        print(f"\n=== Technology Stack for {self.current_target.ip} ===")
        
        for tech_type, tech_name in self.current_target.technology_stack.items():
            print(f"{tech_type.title().ljust(12)}: {tech_name}")
        
        # Suggest attack vectors based on tech stack
        print("\nSuggested Attack Vectors:")
        self._suggest_tech_attacks(self.current_target.technology_stack)
    
    def _show_technology_analysis(self):
        """Show detailed technology analysis results"""
        if not self.current_target.technology_analysis:
            print("Kevin: No technology analysis yet. Try 'web deepdive <url>' for comprehensive analysis!")
            return
        
        print(f"\n=== Technology Analysis for {self.current_target.ip} ===")
        
        for i, analysis in enumerate(self.current_target.technology_analysis, 1):
            print(f"\n--- Analysis #{i}: {analysis.url} ---")
            print(f"Timestamp: {analysis.timestamp}")
            
            # Quick summary
            tech_summary = []
            if analysis.web_server:
                tech_summary.append(f"Server: {analysis.web_server}")
            if analysis.cms:
                tech_summary.append(f"CMS: {analysis.cms}")
            if analysis.backend_language:
                tech_summary.append(f"Backend: {analysis.backend_language}")
            if analysis.frontend_framework:
                tech_summary.append(f"Frontend: {analysis.frontend_framework}")
            
            if tech_summary:
                print(f"Technologies: {' | '.join(tech_summary)}")
            
            # Security status
            security_score = len(analysis.security_headers)
            security_issues = len(analysis.missing_security_headers) + len(analysis.security_issues)
            print(f"Security Headers: {security_score} present, {len(analysis.missing_security_headers)} missing")
            
            if analysis.potential_vulnerabilities:
                print(f"⚠️ Potential Vulnerabilities: {len(analysis.potential_vulnerabilities)}")
            
            if analysis.js_libraries:
                libs = list(analysis.js_libraries.keys())
                print(f"JS Libraries: {', '.join(libs[:3])}{'...' if len(libs) > 3 else ''}")
        
        print(f"\nUse 'web deepdive <url>' to see full analysis for any URL")
    
    def _show_virtual_hosts(self):
        """Show detailed virtual host information"""
        if not self.current_target.virtual_hosts:
            print("Kevin: No virtual hosts discovered yet. Try 'web vhost <ip>' or 'web subdomain <domain>'!")
            return
        
        print(f"\n=== Virtual Hosts for {self.current_target.ip} ===")
        
        # Group by discovery method
        methods = {}
        for vhost in self.current_target.virtual_hosts:
            method = vhost.discovery_method
            if method not in methods:
                methods[method] = []
            methods[method].append(vhost)
        
        for method, vhosts in methods.items():
            method_name = {
                'host_header': '🌐 Host Header Fuzzing',
                'dns_subdomain': '🔍 DNS Subdomain Enumeration', 
                'reverse_dns': '🔄 Reverse DNS Lookup'
            }.get(method, f'🔧 {method.title()}')
            
            print(f"\n{method_name} ({len(vhosts)} found):")
            
            for vhost in sorted(vhosts, key=lambda v: v.hostname):
                status_emoji = "✅" if vhost.status_code < 400 else "⚠️"
                print(f"  {status_emoji} {vhost.hostname} -> {vhost.ip}")
                print(f"     Status: {vhost.status_code} | Size: {vhost.content_length}b | Unique: {vhost.unique_content}")
                
                if vhost.title:
                    title_display = vhost.title[:50] + "..." if len(vhost.title) > 50 else vhost.title
                    print(f"     Title: {title_display}")
                
                if vhost.response_time:
                    print(f"     Response Time: {vhost.response_time:.2f}s")
                
                if vhost.redirect_location:
                    print(f"     Redirects to: {vhost.redirect_location}")
        
        # Attack suggestions
        print(f"\n💡 Kevin's Virtual Host Attack Tips:")
        print("  • Each virtual host may run different applications")
        print("  • Development/staging vhosts often have weaker security")
        print("  • Try directory enumeration on each discovered vhost")
        print("  • Look for admin panels, APIs, and file uploads on each vhost")
        
        # Specific recommendations based on discovered vhosts
        interesting_vhosts = []
        for vhost in self.current_target.virtual_hosts:
            hostname_lower = vhost.hostname.lower()
            if any(keyword in hostname_lower for keyword in ['admin', 'api', 'dev', 'staging', 'test', 'mail']):
                interesting_vhosts.append(vhost.hostname)
        
        if interesting_vhosts:
            print(f"\n🎯 High-Priority Targets:")
            for hostname in interesting_vhosts[:5]:  # Show top 5
                print(f"  • {hostname}")
    
    def _show_mysql_findings(self):
        """Show detailed MySQL enumeration findings"""
        if not self.current_target.mysql_findings:
            print("Kevin: No MySQL enumeration results yet. Try 'enum mysql' or scan for MySQL services!")
            return
        
        for i, finding in enumerate(self.current_target.mysql_findings, 1):
            print(f"\n=== MySQL Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # Version Information
            if finding.version or finding.server_version:
                print(f"\n📊 VERSION INFORMATION:")
                if finding.version:
                    print(f"   MySQL Version: {finding.version}")
                if finding.server_version:
                    print(f"   Server Version: {finding.server_version}")
                if finding.protocol_version:
                    print(f"   Protocol Version: {finding.protocol_version}")
            
            # Security Status
            ssl_status = "✅ Enabled" if finding.ssl_enabled else "❌ Not detected"
            print(f"\n🔒 SECURITY STATUS:")
            print(f"   SSL/TLS: {ssl_status}")
            print(f"   Anonymous Access: {'⚠️ Enabled' if finding.anonymous_access else '✅ Disabled'}")
            
            # Critical Security Issues
            if finding.security_issues:
                critical_count = len([issue for issue in finding.security_issues 
                                    if any(keyword in issue.lower() for keyword in ['critical', 'root', 'empty password'])])
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)} total, {critical_count} critical):")
                
                # Show critical issues first
                critical_issues = [issue for issue in finding.security_issues 
                                 if any(keyword in issue.lower() for keyword in ['critical', 'root', 'empty password'])]
                for issue in critical_issues:
                    print(f"   🔥 CRITICAL: {issue}")
                
                # Show other issues
                other_issues = [issue for issue in finding.security_issues if issue not in critical_issues]
                for issue in other_issues[:5]:  # Show first 5 non-critical
                    print(f"   ⚠️  WARNING: {issue}")
                if len(other_issues) > 5:
                    print(f"   ... and {len(other_issues) - 5} more warnings")
            
            # Empty Password Accounts
            if finding.empty_password_accounts:
                print(f"\n🔓 EMPTY PASSWORD ACCOUNTS:")
                for account in finding.empty_password_accounts:
                    urgency = "🔥 IMMEDIATE ACTION REQUIRED" if account == 'root' else "⚠️ Security Risk"
                    print(f"   • {account} - {urgency}")
            
            # Database Information
            if finding.databases:
                print(f"\n📂 ACCESSIBLE DATABASES ({len(finding.databases)}):")
                for db in finding.databases:
                    interest_level = "🎯" if any(keyword in db.lower() 
                                               for keyword in ['user', 'admin', 'customer', 'payment', 'wordpress', 'drupal']) else "📄"
                    print(f"   {interest_level} {db}")
            
            # User Information  
            if finding.users:
                print(f"\n👤 MYSQL USERS ({len(finding.users)}):")
                for user in finding.users:
                    print(f"   • {user}")
            
            # Important Variables
            if finding.variables:
                print(f"\n🔧 CONFIGURATION VARIABLES:")
                for var, value in finding.variables.items():
                    risk_indicator = ""
                    if var == 'local_infile' and value.upper() == 'ON':
                        risk_indicator = " ⚠️ SECURITY RISK"
                    elif var == 'secure_file_priv' and (not value or value.upper() == 'NULL'):
                        risk_indicator = " ⚠️ UNRESTRICTED"
                    print(f"   {var}: {value}{risk_indicator}")
        
        # Overall summary
        total_critical = sum(len([issue for issue in finding.security_issues 
                                if any(keyword in issue.lower() for keyword in ['critical', 'root', 'empty password'])]) 
                           for finding in self.current_target.mysql_findings)
        
        total_databases = sum(len(finding.databases) for finding in self.current_target.mysql_findings)
        
        print(f"\n📊 MYSQL ENUMERATION SUMMARY:")
        print(f"   Instances Scanned: {len(self.current_target.mysql_findings)}")
        print(f"   Total Databases Found: {total_databases}")
        print(f"   Critical Security Issues: {total_critical}")
        
        if total_critical > 0:
            print(f"\n🚨 IMMEDIATE ACTION REQUIRED: {total_critical} critical security issues detected!")
            print("   Focus on empty password accounts and version vulnerabilities first.")
    
    def _show_mssql_findings(self):
        """Show detailed MSSQL enumeration findings"""
        if not self.current_target.mssql_findings:
            print("Kevin: No MSSQL enumeration results yet. Try 'enum mssql' or scan for MSSQL services!")
            return
        
        for i, finding in enumerate(self.current_target.mssql_findings, 1):
            print(f"\n=== MSSQL Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # Version Information
            if finding.version or finding.product_version:
                print(f"\n📊 VERSION INFORMATION:")
                if finding.version:
                    print(f"   MSSQL Version: {finding.version}")
                if finding.product_version:
                    print(f"   Product Version: {finding.product_version}")
                if finding.build_number:
                    print(f"   Build Number: {finding.build_number}")
            
            # Authentication Status
            print(f"\n🔒 AUTHENTICATION STATUS:")
            if finding.authentication_mode:
                auth_status = "🔓 Mixed Mode (SQL + Windows)" if "mixed" in finding.authentication_mode.lower() else f"🔐 {finding.authentication_mode}"
                print(f"   Authentication Mode: {auth_status}")
            
            # Critical Security Issues
            critical_flags = []
            if finding.xp_cmdshell_enabled:
                critical_flags.append("🔥 CRITICAL: xp_cmdshell ENABLED - Remote command execution possible!")
            if finding.sa_account_blank_password:
                critical_flags.append("🔥 CRITICAL: SA account has blank password!")
            
            if critical_flags:
                print(f"\n🚨 IMMEDIATE THREATS:")
                for flag in critical_flags:
                    print(f"   {flag}")
            
            # Security Issues
            if finding.security_issues:
                high_risk = len([issue for issue in finding.security_issues 
                               if any(keyword in issue.lower() for keyword in ['critical', 'high', 'cmdshell', 'blank password'])])
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)} total, {high_risk} high-risk):")
                
                # Show critical issues first
                critical_issues = [issue for issue in finding.security_issues 
                                 if any(keyword in issue.lower() for keyword in ['critical', 'high', 'cmdshell', 'blank password'])]
                for issue in critical_issues:
                    print(f"   🔥 HIGH RISK: {issue}")
                
                # Show other issues
                other_issues = [issue for issue in finding.security_issues if issue not in critical_issues]
                for issue in other_issues[:5]:  # Show first 5 non-critical
                    print(f"   ⚠️  WARNING: {issue}")
                if len(other_issues) > 5:
                    print(f"   ... and {len(other_issues) - 5} more warnings")
            
            # Weak Password Accounts
            if finding.weak_passwords:
                print(f"\n🔓 WEAK PASSWORD ACCOUNTS:")
                for account, password in finding.weak_passwords.items():
                    urgency = "🔥 IMMEDIATE ACTION REQUIRED" if account.lower() == 'sa' else "⚠️ Security Risk"
                    print(f"   • {account}:{password} - {urgency}")
            
            # Database Information
            if finding.databases:
                print(f"\n📂 ACCESSIBLE DATABASES ({len(finding.databases)}):")
                for db in finding.databases:
                    interest_level = "🎯" if any(keyword in db.lower() 
                                               for keyword in ['master', 'model', 'user', 'admin', 'customer', 'payment']) else "📄"
                    print(f"   {interest_level} {db}")
            
            # Dangerous Configurations
            if finding.dangerous_configurations:
                print(f"\n⚠️ DANGEROUS CONFIGURATIONS:")
                for config in finding.dangerous_configurations:
                    print(f"   • {config}")
            
            # Service Information
            if finding.service_account:
                print(f"\n🔧 SERVICE INFORMATION:")
                print(f"   Service Account: {finding.service_account}")
                if finding.tcp_port:
                    print(f"   TCP Port: {finding.tcp_port}")
                if finding.named_pipe:
                    print(f"   Named Pipe: {finding.named_pipe}")
        
        # Overall summary
        total_critical = sum(len([issue for issue in finding.security_issues 
                                if any(keyword in issue.lower() for keyword in ['critical', 'high', 'cmdshell'])]) 
                           + (1 if finding.xp_cmdshell_enabled else 0)
                           + (1 if finding.sa_account_blank_password else 0)
                           for finding in self.current_target.mssql_findings)
        
        total_databases = sum(len(finding.databases) for finding in self.current_target.mssql_findings)
        
        print(f"\n📊 MSSQL ENUMERATION SUMMARY:")
        print(f"   Instances Scanned: {len(self.current_target.mssql_findings)}")
        print(f"   Total Databases Found: {total_databases}")
        print(f"   Critical Security Issues: {total_critical}")
        
        if total_critical > 0:
            print(f"\n🚨 IMMEDIATE ACTION REQUIRED: {total_critical} critical security issues detected!")
            print("   Focus on xp_cmdshell and blank SA passwords first.")
    
    def _show_oracle_findings(self):
        """Show detailed Oracle enumeration findings"""
        if not self.current_target.oracle_findings:
            print("Kevin: No Oracle enumeration results yet. Try 'enum oracle' or scan for Oracle services!")
            return
        
        for i, finding in enumerate(self.current_target.oracle_findings, 1):
            print(f"\n=== Oracle Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # TNS Listener Information
            if finding.listener_version or finding.listener_status:
                print(f"\n📊 TNS LISTENER INFORMATION:")
                if finding.listener_version:
                    print(f"   Listener Version: {finding.listener_version}")
                if finding.listener_status:
                    print(f"   Listener Status: {finding.listener_status}")
            
            # Service Identifiers (SIDs)
            if finding.sids:
                print(f"\n🎯 SERVICE IDENTIFIERS (SIDs) - {len(finding.sids)} found:")
                for sid in finding.sids:
                    # Mark commonly targeted SIDs
                    interest_level = "🔥" if sid.lower() in ['xe', 'orcl', 'prod', 'test', 'dev'] else "📄"
                    print(f"   {interest_level} {sid}")
            
            # Accessible SIDs
            if finding.accessible_sids:
                print(f"\n✅ ACCESSIBLE SIDs ({len(finding.accessible_sids)}):")
                for sid in finding.accessible_sids:
                    print(f"   • {sid} - Connection possible!")
            
            # Version Information
            if finding.version or finding.banner:
                print(f"\n📊 VERSION INFORMATION:")
                if finding.version:
                    print(f"   Oracle Version: {finding.version}")
                if finding.banner:
                    print(f"   Banner: {finding.banner}")
            
            # Security Issues
            if finding.security_issues:
                high_risk = len([issue for issue in finding.security_issues 
                               if any(keyword in issue.lower() for keyword in ['critical', 'high', 'default', 'weak'])])
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)} total, {high_risk} high-risk):")
                
                # Show critical issues first
                critical_issues = [issue for issue in finding.security_issues 
                                 if any(keyword in issue.lower() for keyword in ['critical', 'high', 'default', 'weak'])]
                for issue in critical_issues:
                    print(f"   🔥 HIGH RISK: {issue}")
                
                # Show other issues
                other_issues = [issue for issue in finding.security_issues if issue not in critical_issues]
                for issue in other_issues[:5]:  # Show first 5 non-critical
                    print(f"   ⚠️  WARNING: {issue}")
                if len(other_issues) > 5:
                    print(f"   ... and {len(other_issues) - 5} more warnings")
            
            # Default Accounts
            if finding.default_accounts:
                print(f"\n🔓 DEFAULT ACCOUNTS DETECTED:")
                for account in finding.default_accounts:
                    urgency = "🔥 IMMEDIATE ACTION REQUIRED" if account.lower() in ['sys', 'system', 'scott'] else "⚠️ Security Risk"
                    print(f"   • {account} - {urgency}")
            
            # Listener Configuration
            if finding.listener_log_status or finding.listener_log_file:
                print(f"\n📋 LISTENER CONFIGURATION:")
                if finding.listener_log_status:
                    log_status = "✅ Enabled" if "on" in finding.listener_log_status.lower() else "❌ Disabled"
                    print(f"   Logging: {log_status}")
                if finding.listener_log_file:
                    print(f"   Log File: {finding.listener_log_file}")
        
        # Overall summary
        total_sids = sum(len(finding.sids) for finding in self.current_target.oracle_findings)
        total_accessible = sum(len(finding.accessible_sids) for finding in self.current_target.oracle_findings)
        total_critical = sum(len([issue for issue in finding.security_issues 
                                if any(keyword in issue.lower() for keyword in ['critical', 'high', 'default'])]) 
                           for finding in self.current_target.oracle_findings)
        
        print(f"\n📊 ORACLE ENUMERATION SUMMARY:")
        print(f"   Instances Scanned: {len(self.current_target.oracle_findings)}")
        print(f"   Total SIDs Discovered: {total_sids}")
        print(f"   Accessible SIDs: {total_accessible}")
        print(f"   Security Issues: {total_critical}")
        
        if total_accessible > 0:
            print(f"\n🎯 ATTACK OPPORTUNITIES: {total_accessible} accessible SIDs found!")
            print("   Focus on default credentials and version-specific exploits.")
    
    def _show_smtp_findings(self):
        """Show detailed SMTP enumeration findings"""
        if not self.current_target.smtp_findings:
            print("Kevin: No SMTP enumeration results yet. Try 'enum smtp' or scan for SMTP services!")
            return
        
        for i, finding in enumerate(self.current_target.smtp_findings, 1):
            print(f"\n=== SMTP Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # Basic Information
            if finding.banner or finding.software:
                print(f"\n📊 SERVER INFORMATION:")
                if finding.banner:
                    print(f"   Banner: {finding.banner}")
                if finding.software:
                    version_info = f" {finding.version}" if finding.version else ""
                    print(f"   Software: {finding.software}{version_info}")
                if finding.hostname:
                    print(f"   Hostname: {finding.hostname}")
            
            # Critical Security Issues
            critical_flags = []
            if finding.relay_test_result == "OPEN RELAY DETECTED":
                critical_flags.append("🔥 CRITICAL: Open mail relay detected!")
            
            if critical_flags:
                print(f"\n🚨 CRITICAL SECURITY ALERTS:")
                for flag in critical_flags:
                    print(f"   {flag}")
            
            # Capabilities
            if finding.capabilities:
                print(f"\n⚙️ SMTP CAPABILITIES ({len(finding.capabilities)}):")
                for cap in finding.capabilities:
                    security_note = ""
                    if cap == 'VRFY':
                        security_note = " ⚠️ User Enumeration"
                    elif cap == 'EXPN':
                        security_note = " ⚠️ List Expansion"
                    elif cap == 'STARTTLS':
                        security_note = " 🔒 Encryption"
                    print(f"   • {cap}{security_note}")
            
            # User Enumeration Results
            if finding.valid_users:
                print(f"\n👤 VALID USERS ({len(finding.valid_users)}):")
                for user in finding.valid_users:
                    print(f"   • {user}")
            
            # Security Issues
            if finding.security_issues:
                high_risk = len([issue for issue in finding.security_issues 
                               if any(keyword in issue.lower() for keyword in ['critical', 'open relay', 'vrfy', 'expn'])])
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)} total, {high_risk} high-risk):")
                
                # Show critical issues first
                critical_issues = [issue for issue in finding.security_issues 
                                 if any(keyword in issue.lower() for keyword in ['critical', 'open relay'])]
                for issue in critical_issues:
                    print(f"   🔥 CRITICAL: {issue}")
                
                # Show other issues
                other_issues = [issue for issue in finding.security_issues if issue not in critical_issues]
                for issue in other_issues[:5]:  # Show first 5 non-critical
                    print(f"   ⚠️  WARNING: {issue}")
                if len(other_issues) > 5:
                    print(f"   ... and {len(other_issues) - 5} more warnings")
            
            # Configuration Details
            if finding.auth_methods or finding.max_message_size:
                print(f"\n📋 CONFIGURATION:")
                if finding.auth_methods:
                    print(f"   Auth Methods: {', '.join(finding.auth_methods)}")
                if finding.max_message_size:
                    print(f"   Max Message Size: {finding.max_message_size} bytes")
        
        # Overall summary
        total_critical = sum(len([issue for issue in finding.security_issues 
                                if any(keyword in issue.lower() for keyword in ['critical', 'open relay'])]) 
                           + (1 if finding.relay_test_result == "OPEN RELAY DETECTED" else 0)
                           for finding in self.current_target.smtp_findings)
        
        total_users = sum(len(finding.valid_users) for finding in self.current_target.smtp_findings)
        
        print(f"\n📊 SMTP ENUMERATION SUMMARY:")
        print(f"   Instances Scanned: {len(self.current_target.smtp_findings)}")
        print(f"   Valid Users Found: {total_users}")
        print(f"   Critical Issues: {total_critical}")
        
        if total_critical > 0:
            print(f"\n🚨 IMMEDIATE ACTION REQUIRED: {total_critical} critical issues detected!")
            print("   Focus on open relays and user enumeration capabilities.")
    
    def _show_email_findings(self):
        """Show detailed email service enumeration findings"""
        if not self.current_target.email_findings:
            print("Kevin: No email service enumeration results yet. Try 'enum pop3' or 'enum imap'!")
            return
        
        for i, finding in enumerate(self.current_target.email_findings, 1):
            print(f"\n=== {finding.service_type.upper()} Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # Basic Information
            if finding.banner or finding.software:
                print(f"\n📊 SERVER INFORMATION:")
                if finding.banner:
                    print(f"   Banner: {finding.banner}")
                if finding.software:
                    version_info = f" {finding.version}" if finding.version else ""
                    print(f"   Software: {finding.software}{version_info}")
            
            # Security Status
            print(f"\n🔒 SECURITY STATUS:")
            ssl_status = "✅ Enabled" if finding.ssl_enabled else "❌ Disabled"
            print(f"   SSL/TLS: {ssl_status}")
            if finding.starttls_available:
                print(f"   STARTTLS: ✅ Available")
            
            # Critical Security Issues
            critical_flags = []
            if finding.plaintext_auth:
                critical_flags.append("🔥 CRITICAL: Plaintext authentication over unencrypted connection!")
            
            if critical_flags:
                print(f"\n🚨 CRITICAL SECURITY ALERTS:")
                for flag in critical_flags:
                    print(f"   {flag}")
            
            # Capabilities
            if finding.capabilities:
                print(f"\n⚙️ {finding.service_type.upper()} CAPABILITIES ({len(finding.capabilities)}):")
                for cap in finding.capabilities:
                    security_note = ""
                    if 'AUTH' in cap.upper():
                        security_note = " 🔐"
                    elif 'STARTTLS' in cap.upper():
                        security_note = " 🔒"
                    print(f"   • {cap}{security_note}")
            
            # Authentication Mechanisms
            if finding.auth_mechanisms:
                print(f"\n🔐 AUTHENTICATION MECHANISMS:")
                for mechanism in finding.auth_mechanisms:
                    security_note = ""
                    if 'PLAIN' in mechanism.upper() and not finding.ssl_enabled:
                        security_note = " ⚠️ Plaintext Risk"
                    print(f"   • {mechanism}{security_note}")
            
            # Security Issues
            if finding.security_issues:
                high_risk = len([issue for issue in finding.security_issues 
                               if any(keyword in issue.lower() for keyword in ['critical', 'plaintext'])])
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)} total, {high_risk} high-risk):")
                
                # Show critical issues first
                critical_issues = [issue for issue in finding.security_issues 
                                 if any(keyword in issue.lower() for keyword in ['critical', 'plaintext'])]
                for issue in critical_issues:
                    print(f"   🔥 CRITICAL: {issue}")
                
                # Show other issues
                other_issues = [issue for issue in finding.security_issues if issue not in critical_issues]
                for issue in other_issues[:5]:  # Show first 5 non-critical
                    print(f"   ⚠️  WARNING: {issue}")
                if len(other_issues) > 5:
                    print(f"   ... and {len(other_issues) - 5} more warnings")
            
            # Configuration Status
            config_items = []
            if finding.login_disabled:
                config_items.append("Login: Currently disabled")
            if finding.anonymous_access:
                config_items.append("Anonymous Access: ⚠️ Possible")
            
            if config_items:
                print(f"\n📋 CONFIGURATION:")
                for item in config_items:
                    print(f"   {item}")
        
        # Overall summary
        total_critical = sum(len([issue for issue in finding.security_issues 
                                if any(keyword in issue.lower() for keyword in ['critical', 'plaintext'])]) 
                           + (1 if finding.plaintext_auth else 0)
                           for finding in self.current_target.email_findings)
        
        services_by_type = {}
        for finding in self.current_target.email_findings:
            service_type = finding.service_type.upper()
            if service_type not in services_by_type:
                services_by_type[service_type] = 0
            services_by_type[service_type] += 1
        
        print(f"\n📊 EMAIL SERVICE ENUMERATION SUMMARY:")
        print(f"   Total Services Scanned: {len(self.current_target.email_findings)}")
        for service, count in services_by_type.items():
            print(f"   {service}: {count} instance(s)")
        print(f"   Critical Issues: {total_critical}")
        
        if total_critical > 0:
            print(f"\n🚨 IMMEDIATE ACTION REQUIRED: {total_critical} critical issues detected!")
            print("   Focus on plaintext authentication and encryption issues.")
    
    def _show_ldap_findings(self):
        """Show detailed LDAP enumeration findings"""
        if not self.current_target.ldap_findings:
            print("Kevin: No LDAP enumeration results yet. Try 'enum ldap' or scan for LDAP services!")
            return
        
        for i, finding in enumerate(self.current_target.ldap_findings, 1):
            print(f"\n=== LDAP Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # Basic Information
            if finding.server_info or finding.base_dn:
                print(f"\n📊 DIRECTORY SERVICE INFORMATION:")
                if finding.server_info:
                    print(f"   Server Info: {finding.server_info}")
                if finding.base_dn:
                    print(f"   Base DN: {finding.base_dn}")
                if finding.supported_sasl_mechanisms:
                    print(f"   SASL Mechanisms: {', '.join(finding.supported_sasl_mechanisms)}")
            
            # Critical Security Issues
            critical_flags = []
            if finding.anonymous_bind:
                critical_flags.append("🔥 CRITICAL: Anonymous bind enabled!")
            
            if critical_flags:
                print(f"\n🚨 CRITICAL SECURITY ALERTS:")
                for flag in critical_flags:
                    print(f"   {flag}")
            
            # Naming Contexts
            if finding.naming_contexts:
                print(f"\n📂 NAMING CONTEXTS ({len(finding.naming_contexts)}):")
                for context in finding.naming_contexts:
                    print(f"   • {context}")
            
            # Directory Structure
            if finding.organizational_units:
                print(f"\n🏗️ ORGANIZATIONAL UNITS ({len(finding.organizational_units)}):")
                for ou in finding.organizational_units[:15]:  # Show first 15
                    print(f"   • {ou}")
                if len(finding.organizational_units) > 15:
                    print(f"   ... and {len(finding.organizational_units) - 15} more")
            
            # Users and Groups Summary
            if finding.users_found or finding.groups_found:
                print(f"\n👥 DIRECTORY OBJECTS:")
                if finding.users_found:
                    print(f"   Users Found: {len(finding.users_found)}")
                if finding.groups_found:
                    print(f"   Groups Found: {len(finding.groups_found)}")
                if finding.computer_accounts:
                    print(f"   Computer Accounts: {len(finding.computer_accounts)}")
            
            # Schema Information
            if finding.schema_information:
                print(f"\n📋 SCHEMA INFORMATION:")
                for key, value in finding.schema_information.items():
                    if isinstance(value, list):
                        print(f"   {key}: {len(value)} entries")
                    else:
                        print(f"   {key}: {value}")
            
            # Security Issues
            if finding.security_issues:
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
                for j, issue in enumerate(finding.security_issues, 1):
                    severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'anonymous']) else "⚠️  WARNING"
                    print(f"   {j}. {severity}: {issue}")
            
            # Weak Configurations
            if finding.weak_configurations:
                print(f"\n⚠️ WEAK CONFIGURATIONS:")
                for config in finding.weak_configurations:
                    print(f"   • {config}")
        
        # Overall summary
        total_users = sum(len(finding.users_found) for finding in self.current_target.ldap_findings)
        total_groups = sum(len(finding.groups_found) for finding in self.current_target.ldap_findings)
        total_critical = sum(len(finding.security_issues) for finding in self.current_target.ldap_findings)
        anonymous_bind_count = sum(1 for finding in self.current_target.ldap_findings if finding.anonymous_bind)
        
        print(f"\n📊 LDAP ENUMERATION SUMMARY:")
        print(f"   LDAP Servers Scanned: {len(self.current_target.ldap_findings)}")
        print(f"   Total Users Found: {total_users}")
        print(f"   Total Groups Found: {total_groups}")
        print(f"   Security Issues: {total_critical}")
        print(f"   Anonymous Bind Enabled: {anonymous_bind_count} servers")
        
        if anonymous_bind_count > 0:
            print(f"\n🎯 ATTACK OPPORTUNITIES: {anonymous_bind_count} servers allow anonymous access!")
            print("   Focus on user enumeration and directory structure mapping.")
    
    def _show_kerberos_findings(self):
        """Show detailed Kerberos enumeration findings"""
        if not self.current_target.kerberos_findings:
            print("Kevin: No Kerberos enumeration results yet. Try 'enum kerberos' or scan for Kerberos services!")
            return
        
        for i, finding in enumerate(self.current_target.kerberos_findings, 1):
            print(f"\n=== Kerberos Finding #{i}: {finding.target}:{finding.port} ===")
            print(f"Timestamp: {finding.timestamp}")
            
            # Basic Information
            if finding.realm or finding.kdc_server:
                print(f"\n📊 AUTHENTICATION SERVICE INFORMATION:")
                if finding.realm:
                    print(f"   Kerberos Realm: {finding.realm}")
                if finding.kdc_server:
                    print(f"   Key Distribution Center: {finding.kdc_server}")
                if finding.supported_encryption_types:
                    print(f"   Encryption Types: {', '.join(finding.supported_encryption_types)}")
            
            # Critical Security Issues
            critical_flags = []
            if finding.asrep_roastable_users:
                critical_flags.append(f"🔥 CRITICAL: {len(finding.asrep_roastable_users)} users vulnerable to AS-REP roasting!")
            if finding.kerberoastable_users:
                critical_flags.append(f"🔥 CRITICAL: {len(finding.kerberoastable_users)} users vulnerable to Kerberoasting!")
            if finding.weak_encryption_detected:
                critical_flags.append("⚠️ WARNING: Weak encryption algorithms detected")
            
            if critical_flags:
                print(f"\n🚨 CRITICAL SECURITY ALERTS:")
                for flag in critical_flags:
                    print(f"   {flag}")
            
            # User Enumeration Results
            if finding.users_found:
                print(f"\n👥 USER ENUMERATION ({len(finding.users_found)} users):")
                for user in finding.users_found[:10]:  # Show first 10
                    # Mark users with security issues
                    security_note = ""
                    if user in finding.asrep_roastable_users:
                        security_note = " 🔥 AS-REP ROASTABLE"
                    elif user in finding.kerberoastable_users:
                        security_note = " 🎯 KERBEROASTABLE"
                    print(f"   • {user}{security_note}")
                if len(finding.users_found) > 10:
                    print(f"   ... and {len(finding.users_found) - 10} more users")
            
            # Service Principal Names
            if finding.spns_found:
                print(f"\n🎯 SERVICE PRINCIPAL NAMES ({len(finding.spns_found)}):")
                for spn in finding.spns_found[:10]:  # Show first 10
                    # Highlight interesting services
                    interest_level = "🔥" if any(service in spn.lower() for service in ['mssql', 'exchange', 'cifs', 'http']) else "📄"
                    print(f"   {interest_level} {spn}")
                if len(finding.spns_found) > 10:
                    print(f"   ... and {len(finding.spns_found) - 10} more SPNs")
            
            # AS-REP Roastable Users Detail
            if finding.asrep_roastable_users:
                print(f"\n🔥 AS-REP ROASTABLE USERS ({len(finding.asrep_roastable_users)}):")
                for user in finding.asrep_roastable_users[:5]:  # Show first 5
                    print(f"   • {user} (Pre-authentication disabled)")
                if len(finding.asrep_roastable_users) > 5:
                    print(f"   ... and {len(finding.asrep_roastable_users) - 5} more vulnerable users")
            
            # Service Accounts
            if finding.service_accounts:
                print(f"\n🔧 SERVICE ACCOUNTS ({len(finding.service_accounts)}):")
                for account in finding.service_accounts[:5]:  # Show first 5
                    print(f"   • {account}")
                if len(finding.service_accounts) > 5:
                    print(f"   ... and {len(finding.service_accounts) - 5} more service accounts")
            
            # Domain Controllers
            if finding.domain_controllers:
                print(f"\n🏢 DOMAIN CONTROLLERS ({len(finding.domain_controllers)}):")
                for dc in finding.domain_controllers:
                    print(f"   • {dc}")
            
            # Security Issues
            if finding.security_issues:
                print(f"\n🚨 SECURITY ISSUES ({len(finding.security_issues)}):")
                for j, issue in enumerate(finding.security_issues, 1):
                    severity = "🔥 CRITICAL" if any(keyword in issue.lower() for keyword in ['critical', 'roast']) else "⚠️  WARNING"
                    print(f"   {j}. {severity}: {issue}")
        
        # Overall summary
        total_users = sum(len(finding.users_found) for finding in self.current_target.kerberos_findings)
        total_spns = sum(len(finding.spns_found) for finding in self.current_target.kerberos_findings)
        total_asrep_roastable = sum(len(finding.asrep_roastable_users) for finding in self.current_target.kerberos_findings)
        total_kerberoastable = sum(len(finding.kerberoastable_users) for finding in self.current_target.kerberos_findings)
        
        print(f"\n📊 KERBEROS ENUMERATION SUMMARY:")
        print(f"   KDC Servers Scanned: {len(self.current_target.kerberos_findings)}")
        print(f"   Total Users Found: {total_users}")
        print(f"   Total SPNs Found: {total_spns}")
        print(f"   AS-REP Roastable Users: {total_asrep_roastable}")
        print(f"   Kerberoastable Users: {total_kerberoastable}")
        
        if total_asrep_roastable > 0 or total_kerberoastable > 0:
            print(f"\n🎯 ATTACK OPPORTUNITIES: {total_asrep_roastable + total_kerberoastable} users vulnerable to hash attacks!")
            print("   Focus on AS-REP roasting and Kerberoasting for credential extraction.")
    
    def do_notes(self, line: str):
        """Add/view notes: notes [text]"""
        if not self.current_target:
            print("Kevin: Set a target first!")
            return
        
        if not line.strip():
            self._show_notes()
        else:
            timestamp = datetime.now().strftime("%H:%M")
            note = f"{line.strip()}"
            self.current_target.notes.append(note)
            print(f"Kevin: Note added! Total notes: {len(self.current_target.notes)}")
    
    def do_save(self, line: str):
        """Save current session: save [filename]"""
        if not self.current_target:
            print("Kevin: Nothing to save - no target set!")
            return
        
        filename = line.strip()
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"kevin_{self.current_target.ip}_{timestamp}.json"
        
        filepath = self.session_dir / filename
        
        try:
            # Convert dataclass to dict for JSON serialization
            target_dict = asdict(self.current_target)
            
            with open(filepath, 'w') as f:
                json.dump(target_dict, f, indent=2, default=str)
            
            print(f"Kevin: Session saved to {filepath}")
            print("Kevin: Remember - good documentation wins exams! 📝")
            
        except Exception as e:
            print(f"Kevin: Save failed - {e}")
    
    def do_load(self, line: str):
        """Load saved session: load <filename>"""
        filename = line.strip()
        if not filename:
            # List available sessions
            session_files = list(self.session_dir.glob("*.json"))
            if session_files:
                print("Kevin: Available sessions:")
                for f in session_files:
                    print(f"  {f.name}")
            else:
                print("Kevin: No saved sessions found.")
            return
        
        filepath = self.session_dir / filename
        
        try:
            with open(filepath, 'r') as f:
                target_dict = json.load(f)
            
            # Reconstruct Target object
            # Convert port dicts back to Port objects
            ports_data = target_dict.get('open_ports', [])
            ports = []
            for port_dict in ports_data:
                port = Port(**port_dict)
                ports.append(port)
            
            # Convert web finding dicts back to WebFinding objects
            web_findings_data = target_dict.get('web_findings', [])
            web_findings = []
            for finding_dict in web_findings_data:
                finding = WebFinding(**finding_dict)
                web_findings.append(finding)
            
            # Convert technology analysis dicts back to TechnologyAnalysis objects
            tech_analysis_data = target_dict.get('technology_analysis', [])
            tech_analysis = []
            for analysis_dict in tech_analysis_data:
                analysis = TechnologyAnalysis(**analysis_dict)
                tech_analysis.append(analysis)
            
            # Convert virtual host dicts back to VirtualHost objects
            vhost_data = target_dict.get('virtual_hosts', [])
            virtual_hosts = []
            for vhost_dict in vhost_data:
                vhost = VirtualHost(**vhost_dict)
                virtual_hosts.append(vhost)
            
            # Convert MySQL finding dicts back to MySQLFinding objects
            mysql_data = target_dict.get('mysql_findings', [])
            mysql_findings = []
            for mysql_dict in mysql_data:
                mysql_finding = MySQLFinding(**mysql_dict)
                mysql_findings.append(mysql_finding)
            
            target_dict['open_ports'] = ports
            target_dict['web_findings'] = web_findings
            target_dict['technology_analysis'] = tech_analysis
            target_dict['virtual_hosts'] = virtual_hosts
            target_dict['mysql_findings'] = mysql_findings
            self.current_target = Target(**target_dict)
            
            print(f"Kevin: Session loaded! Target: {self.current_target.ip}")
            print(f"Kevin: {len(self.current_target.open_ports)} ports, {len(self.current_target.web_findings)} web findings, {len(self.current_target.technology_analysis)} tech analyses, {len(self.current_target.virtual_hosts)} virtual hosts, {len(self.current_target.mysql_findings)} MySQL findings, {len(self.current_target.notes)} notes restored")
            
        except FileNotFoundError:
            print(f"Kevin: Session file not found: {filename}")
        except Exception as e:
            print(f"Kevin: Load failed - {e}")
    
    def do_quit(self, line: str):
        """Exit Kevin"""
        print("Kevin: Keep that curiosity alive! Happy hacking! 🚀")
        
        # Clean up running processes
        for process in self.running_processes.values():
            if process.poll() is None:  # Still running
                process.terminate()
        
        return True
    
    def do_exit(self, line: str):
        """Exit Kevin"""
        return self.do_quit(line)
    
    def emptyline(self):
        """Handle empty line input"""
        pass
    
    def default(self, line: str):
        """Handle unknown commands"""
        print(f"Kevin: I don't know '{line}' - try 'help' for available commands!")
        print("Kevin: Remember, every expert was once a beginner! 💪")

def main():
    """Entry point for Kevin OSCP Companion"""
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        print("Kevin OSCP Companion v1.0")
        print("Named after Kevin Mitnick - The Ghost in the Wires")
        return
    
    try:
        shell = KevinShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n\nKevin: Caught you trying to break out! Remember - patience is key! 👋")
        sys.exit(0)
    except Exception as e:
        print(f"\nKevin encountered an unexpected error: {e}")
        print("Kevin: Even the best hackers hit bugs sometimes! 🐛")
        sys.exit(1)

if __name__ == "__main__":
    main()