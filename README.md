This script executes ssh-audit on multiple IP addresses and parses the results providing an output showing each IP address and their weak ciphers in XLSX and CSV form. These can be used during pentest engagements.
There are two versions of output (vertical and horizontal) - See example outputs
Requirements - install ssh-audit - apt install ssh-audit

To run the script

python3 ssh_analyser.py --ip-file ips.txt --vertical-display
python3 ssh_analyser.py --ip-file ips.txt --horizontal-display



