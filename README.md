# SSL Certificate Diagnostic Tool

A Python-based diagnostic tool for analyzing SSL/TLS certificates across multiple endpoints. This tool helps system administrators and developers verify SSL configurations and certificate validity.

## Features

- Validates SSL certificates for multiple endpoints
- Retrieves complete certificate chains
- Checks certificate expiration dates
- Verifies hostname validation
- Provides cipher and protocol information
- Exports detailed results to JSON format
- Supports both HTTPS and WSS endpoints

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-repo/ssl-diagnostic.git
cd ssl-diagnostic
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

To run the tool, use the following command:

```bash
python ssl_diagnostic.py 
```

### Customize the endpoints

Check specific endpoints:

```bash
python ssl_diagnostic.py --endpoints "wss://example1.com" "wss://example2.com"

```

### Custom Output File

Specify a custom output file:

```bash
python ssl_diagnostic.py --output my_results.json
```

## Example Output

### Console Output

SSL Diagnostic Results Summary:
==================================================

Endpoint: wss://xrpl.ws
Certificate chain verified
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Expired: No

Endpoint: wss://s1.ripple.com
Certificate chain verified
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Expired: No

Endpoint: wss://s2.ripple.com
Certificate chain verified
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Expired: No

Endpoint: wss://xrplcluster.com
Certificate chain verified
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Expired: No

### JSON Output

{
  "wss://xrpl.ws": {
    "timestamp": "2024-12-30T10:45:11.595549",
    "url": "wss://xrpl.ws",
    "hostname": "xrpl.ws",
    "port": 443,
    "ssl_version": "OpenSSL 3.0.15 3 Sep 2024",
    "cert_store": "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages/certifi/cacert.pem",
    "cert_chain": [],
    "verification": {
      "hostname": true,
      "expired": false
    },
    "errors": [],
    "cipher": {
      "name": "TLS_AES_256_GCM_SHA384",
      "version": "TLSv1.3",
      "bits": 256
    },
    "protocol": "TLSv1.3"
  },
  "wss://s1.ripple.com": {
    "timestamp": "2024-12-30T10:45:11.706418",
    "url": "wss://s1.ripple.com",
    "hostname": "s1.ripple.com",
    "port": 443,
    "ssl_version": "OpenSSL 3.0.15 3 Sep 2024",
    "cert_store": "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages/certifi/cacert.pem",
    "cert_chain": [],
    "verification": {
      "hostname": true,
      "expired": false
    },
    "errors": [],
    "cipher": {
      "name": "TLS_AES_256_GCM_SHA384",
      "version": "TLSv1.3",
      "bits": 256
    },
    "protocol": "TLSv1.3"
  },
  "wss://s2.ripple.com": {
    "timestamp": "2024-12-30T10:45:11.886892",
    "url": "wss://s2.ripple.com",
    "hostname": "s2.ripple.com",
    "port": 443,
    "ssl_version": "OpenSSL 3.0.15 3 Sep 2024",
    "cert_store": "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages/certifi/cacert.pem",
    "cert_chain": [],
    "verification": {
      "hostname": true,
      "expired": false
    },
    "errors": [],
    "cipher": {
      "name": "TLS_AES_256_GCM_SHA384",
      "version": "TLSv1.3",
      "bits": 256
    },
    "protocol": "TLSv1.3"
  },
  "wss://xrplcluster.com": {
    "timestamp": "2024-12-30T10:45:12.072866",
    "url": "wss://xrplcluster.com",
    "hostname": "xrplcluster.com",
    "port": 443,
    "ssl_version": "OpenSSL 3.0.15 3 Sep 2024",
    "cert_store": "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages/certifi/cacert.pem",
    "cert_chain": [],
    "verification": {
      "hostname": true,
      "expired": false
    },
    "errors": [],
    "cipher": {
      "name": "TLS_AES_256_GCM_SHA384",
      "version": "TLSv1.3",
      "bits": 256
    },
    "protocol": "TLSv1.3"
  }
}

## Error Handling

The tool provides detailed error messages for common issues:
- Invalid certificates
- Expired certificates
- Hostname mismatches
- Connection failures
- Protocol errors

## Requirements

- Python 3.7 or higher
- Dependencies listed in requirements.txt
- Network access to endpoints being tested

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Junaid Ackroyd (@junaidackroyd)



