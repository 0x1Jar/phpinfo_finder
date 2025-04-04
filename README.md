# 🔍 PHP Info Scanner 🔍

This script scans a given IP range for `phpinfo.php` files. 🌐

## 🚀 Usage

```bash
python3 phpinfo_scanner.py <ip_range_in_cidr> [-o OUTPUT_FILE]
```

📋 Arguments:
- `<ip_range_in_cidr>`: IP range in CIDR notation (required)
- `-o, --output`: Output file to save scan results (optional). If not specified, results will only be displayed in the console

✨ Examples:

```bash
# Basic scan
python3 phpinfo_scanner.py 192.168.1.0/24

# Scan with custom output file
python3 phpinfo_scanner.py 192.168.1.0/24 -o my_scan_results
```

📁 If the `-o` option is specified, the scan will generate the following files:
- Your specified output file: Contains all scan results with status codes
- Your specified output file with "_phpinfo" suffix: Contains only successful phpinfo.php findings

⚠️ Regardless of the `-o` option, the scan will always generate:
- `error_log.txt`: Contains detailed error messages

## 📦 Requirements

*   Python 3.x
*   pip
*   requests
*   ipaddress
*   dotenv

## 📜 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
