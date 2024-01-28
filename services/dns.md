## Attacking DNS

|**Command**|**Description**|
|-|-|
| `dig ns <domain.tld> @<nameserver>` | NS request to the specific nameserver. |
| `dig any <domain.tld> @<nameserver>` | ANY request to the specific nameserver. |
| `dig AXFR <domain.tld> @<nameserver>` | Perform an AXFR zone transfer attempt against a specific name server. |
| `subfinder -d <domain.tld> -v` | Brute-forcing subdomains. |
| `host support.inlanefreight.com` | DNS lookup for the specified subdomain. |
| `dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>` | Subdomain brute forcing. |
| `fierce --domain zonetransfer.me` | To enumerate all DNS servers of the root domain and scan for a DNS zone transfer |
| `./subfinder -d inlanefreight.com -v` | Subdomain Enumeration |
