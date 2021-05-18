#!/usr/bin/python3

from certbot_dns_metaname import MetanameApiClient

if __name__ == "__main__":
    client = MetanameApiClient("k6gp", "Vu0jp540J0VaLnyHpvtK4EQWZsY1MQy9qW7e8zgzV7L27FG8", endpoint="https://test.metaname.net/api/1.1")
    print(client.request("dns_zones"))
