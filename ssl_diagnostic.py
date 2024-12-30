import ssl
import socket
import json
import datetime
import argparse
import urllib.parse
from typing import Dict, Any
import certifi
import OpenSSL.SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLDiagnostic:
    def __init__(self, endpoints: list = None):
        """Initialize with list of endpoints to check"""
        self.endpoints = endpoints or [
            "wss://xrpl.ws",
            "wss://s1.ripple.com",
            "wss://s2.ripple.com",
            "wss://xrplcluster.com"
        ]
        self.results = {}
        
    def check_endpoint(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive SSL check on a single endpoint"""
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme in ['https', 'wss'] else 80)
        
        result = {
            "timestamp": datetime.datetime.now().isoformat(),
            "url": url,
            "hostname": hostname,
            "port": port,
            "ssl_version": ssl.OPENSSL_VERSION,
            "cert_store": certifi.where(),
            "cert_chain": [],
            "verification": {},
            "errors": []
        }

        try:
            # Create SSL context with highest available protocol
            context = ssl.create_default_context(cafile=certifi.where())
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Get certificate chain
                    cert_chain = self._get_cert_chain(hostname, port)
                    result["cert_chain"] = [{
                        "subject": str(c.subject),
                        "issuer": str(c.issuer),
                        "not_before": c.not_valid_before.isoformat(),
                        "not_after": c.not_valid_after.isoformat(),
                        "serial_number": str(c.serial_number),
                        "version": c.version
                    } for c in cert_chain]
                    
                    # Verify hostname
                    result["verification"]["hostname"] = True
                    
                    # Check expiration
                    now = datetime.datetime.now()
                    result["verification"]["expired"] = \
                        now < cert.not_valid_before or now > cert.not_valid_after
                    
                    # Get cipher info
                    result["cipher"] = {
                        "name": ssock.cipher()[0],
                        "version": ssock.cipher()[1],
                        "bits": ssock.cipher()[2]
                    }
                    
                    # Get protocol version
                    result["protocol"] = ssock.version()

        except Exception as e:
            result["errors"].append(str(e))
            
        return result

    def _get_cert_chain(self, hostname: str, port: int) -> list:
        """Get the full certificate chain for a host"""
        cert_chain = []
        try:
            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_METHOD)
            ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda *args: True)
            
            conn = OpenSSL.SSL.Connection(ctx, socket.socket())
            conn.set_tlsext_host_name(hostname.encode())
            conn.connect((hostname, port))
            conn.do_handshake()
            
            for cert in conn.get_peer_cert_chain():
                cert_data = x509.load_der_x509_certificate(
                    OpenSSL.SSL.dump_certificate(OpenSSL.SSL.FILETYPE_ASN1, cert),
                    default_backend()
                )
                cert_chain.append(cert_data)
                
        except Exception as e:
            print(f"Error getting cert chain: {e}")
            
        return cert_chain

    def run_diagnostics(self) -> Dict[str, Any]:
        """Run diagnostics on all configured endpoints"""
        for endpoint in self.endpoints:
            self.results[endpoint] = self.check_endpoint(endpoint)
        return self.results
    
    def save_results(self, filename: str = "ssl_diagnostics.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description='SSL Certificate Diagnostic Tool for Post Fiat Wallet'
    )
    parser.add_argument(
        '--endpoints', 
        nargs='+',
        help='Space-separated list of endpoints to check'
    )
    parser.add_argument(
        '--output',
        default='ssl_diagnostics.json',
        help='Output JSON file path'
    )
    args = parser.parse_args()

    diagnostic = SSLDiagnostic(args.endpoints)
    results = diagnostic.run_diagnostics()
    diagnostic.save_results(args.output)
    
    # Print summary
    print("\nSSL Diagnostic Results Summary:")
    print("=" * 50)
    for endpoint, result in results.items():
        print(f"\nEndpoint: {endpoint}")
        if result['errors']:
            print("ERROR:", ", ".join(result['errors']))
        else:
            print("Certificate chain verified")
            print(f"Protocol: {result['protocol']}")
            print(f"Cipher: {result['cipher']['name']}")
            exp = "Yes" if result['verification']['expired'] else "No"
            print(f"Expired: {exp}")
    print("\nFull results saved to:", args.output)

if __name__ == "__main__":
    main() 