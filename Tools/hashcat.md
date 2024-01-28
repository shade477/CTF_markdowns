## Password attacks
| **Command** | **Description** |
|-------------|-----------------|
| `hashcat --force <password_wordlist> -r <rule_list> --stdout \| sort -u > <filename>` | Creates a mutalated wordlist. |
| `hashcat -m <hash_type> <hashes_file> <wordlist>` | Cracks hashes using the wordlist |

[hashcat_wiki](https://hashcat.net/wiki/doku.php?id=example_hashes) for selecting hash type.
