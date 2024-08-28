import subprocess
import csv
import pandas as pd
import argparse

def run_ssh_audit(ip):
    """
    Run ssh-audit on the specified IP address and return lines containing 'FAIL'.
    """
    try:
        # Run the ssh-audit command for the given IP address
        print(f"Running ssh-audit on {ip}...")
        result = subprocess.run(['ssh-audit', ip], capture_output=True, text=True, check=True)
        
        # Analyze the standard output to find 'fail'
        fail_lines = [line for line in result.stdout.splitlines() if 'fail' in line]
        categorized_failures = []

        # Classify each failure line
        for line in fail_lines:
            classification = classify_failures(line)
            if classification:
                categorized_failures.append(classification)
        
        return categorized_failures

    except subprocess.CalledProcessError as e:
        # In case of error, analyze the standard output
        
        fail_lines = [line for line in e.stdout.splitlines() if 'fail' in line]
        categorized_failures = []

        # Classify each failure line
        for line in fail_lines:
            classification = classify_failures(line)
            if classification:
                categorized_failures.append(classification)
        
        return categorized_failures


def classify_failures(line):
    """
    Classify failure lines into categories based on their prefixes.
    Returns a tuple of the description and the relevant part of the line.
    """
    categories = {
        '(kex)': 'Weak Key Exchange Algorithms Supported',
        '(key)': 'Weak Host-Key Algorithms Supported',
        '(enc)': 'Weak Encryption Ciphers Supported',
        '(mac)': 'Weak MAC Algorithms Supported'
    }
    
    stripped_line = line.lstrip()
    
    # Adjust to start checking from the 8th character
    relevant_part = stripped_line[7:]
    
    for prefix, description in categories.items():
        if relevant_part.startswith(prefix):
            # Extract the part between the prefix and the delimiter '--'
            try:
                start_index = relevant_part.index(prefix) + len(prefix)
                end_index = relevant_part.index('--')
                extracted_relevant_part = relevant_part[start_index:end_index].strip()
                return description, extracted_relevant_part
            except ValueError:
                return description, "Parsing Error"

    return None  # Return None if no match is found


def audit_vertical(ip_list):
    """
    Audit multiple IP addresses, aggregate classified failures, and prepare vertical results.
    """
    ip_issues = {}

    for ip in ip_list:
        print(f"Auditing {ip}...")
        categorized_failures = run_ssh_audit(ip)
        
        # Use a set to ensure unique issues for each IP
        unique_issues = set(categorized_failures)
        
        if unique_issues:
            ip_issues[ip] = unique_issues
        else:
            ip_issues[ip] = {("No issues found", "")}

        print('-' * 40)

    # Prepare results for CSV/Excel export
    results = []
    for ip, issues in ip_issues.items():
        if issues == {("No issues found", "")}:
            results.append([ip, "No issues found", ""])
        else:
            for description, relevant_part in issues:
                results.append([ip, description, relevant_part])
    
    # Export results to CSV
    with open('ssh_audit_results.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['IP Address', 'Issues', 'Algorithms'])
        csv_writer.writerows(results)
    
    # Export results to Excel
    df = pd.DataFrame(results, columns=['IP Address', 'Issues', 'Algorithms'])
    df.to_excel('ssh_audit_results.xlsx', index=False)
    print("Files 'ssh_audit_results.csv' and 'ssh_audit_results.xlsx' are now available in vertical display")

def audit_horizontal(ip_list):
    """
    Audit multiple IP addresses, aggregate classified failures, and prepare horizontal results.
    """
    results = []

    for ip in ip_list:
        print(f"Auditing {ip}...")
        categorized_failures = run_ssh_audit(ip)
        
        # Dictionary to store whether an issue exists for each category
        issue_summary = {
            'Weak Key Exchange Algorithms Supported': '',
            'Weak Host-Key Algorithms Supported': '',
            'Weak Encryption Ciphers Supported': '',
            'Weak MAC Algorithms Supported': ''
        }

        for description, relevant_part in categorized_failures:
            if description in issue_summary:
                issue_summary[description] += relevant_part + ', '

        # Strip trailing comma and space
        for key in issue_summary:
            issue_summary[key] = issue_summary[key].rstrip(', ')

        results.append([
            ip,
            issue_summary['Weak Key Exchange Algorithms Supported'],
            issue_summary['Weak Host-Key Algorithms Supported'],
            issue_summary['Weak Encryption Ciphers Supported'],
            issue_summary['Weak MAC Algorithms Supported']
        ])
        
        print('-' * 40)

    # Export results to CSV
    with open('ssh_audit_results.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([
            'IP Address',
            'Weak Key Exchange Algorithms Supported',
            'Weak Host-Key Algorithms Supported',
            'Weak Encryption Ciphers Supported',
            'Weak MAC Algorithms Supported'
        ])
        csv_writer.writerows(results)
    
    # Export results to Excel
    df = pd.DataFrame(results, columns=[
        'IP Address',
        'Weak Key Exchange Algorithms Supported',
        'Weak Host-Key Algorithms Supported',
        'Weak Encryption Ciphers Supported',
        'Weak MAC Algorithms Supported'
    ])
    df.to_excel('ssh_audit_results.xlsx', index=False)
    print("Files 'ssh_audit_results.csv' and 'ssh_audit_results.xlsx' are now available in horizontal display")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SSH audit script with display options")
    parser.add_argument('--ip-file', required=True, help='Path to the file containing IP addresses, one per line.')
    parser.add_argument('--vertical-display', action='store_true', help='Display results in vertical format (IP, Issue, Algorithm).')
    parser.add_argument('--horizontal-display', action='store_true', help='Display results in horizontal format (IP, Issue1, Issue2, ...).')
    args = parser.parse_args()

    # Read IP addresses from the specified file
    with open(args.ip_file, 'r') as file:
        ips_to_audit = [line.strip() for line in file if line.strip()]

    if args.vertical_display:
        audit_vertical(ips_to_audit)
    elif args.horizontal_display:
        audit_horizontal(ips_to_audit)
    else:
        print("Please specify either --vertical-display or --horizontal-display.")

if __name__ == '__main__':
    main()