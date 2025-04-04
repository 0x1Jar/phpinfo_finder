# PHP Info Scanner

This script scans a given IP range for `phpinfo.php` files.

## Usage

```bash
python phpinfo_scanner.py <ip_range_in_cidr>
```

For example:

```bash
python phpinfo_scanner.py 192.168.1.0/24
```

## Requirements

*   Python 3.x
*   pip
*   requests
*   ipaddress
*   dotenv

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
