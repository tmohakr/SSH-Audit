This script executes ssh-audit on multiple IP addresses and parses the results providing an output showing each IP address and their weak ciphers in XLSX and CSV form. These can be used during pentest engagements.
There are two versions of output (vertical and horizontal) - See example outputs

Requirements -install ssh-audit 
_**apt install ssh-audit**_

To run the script

_python3 ssh_analyser.py --ip-file ips.txt --vertical-display
python3 ssh_analyser.py --ip-file ips.txt --horizontal-display_



