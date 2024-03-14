import dns.resolver
from sys import argv
# Usage: wget https://downloads.majesticseo.com/majestic_million.csv
# Usage: for line in $(cat majestic_million.csv | cut -f 3 -d ',' | tail -n +2); do python3 mailfail.py "$line"; done

# ANSI escape codes for colors
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'

def check_spf(domain):
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        spfRecordExists = False
        for record in spf_records:
            if "v=spf1" in record.to_text():
                spfRecordExists = True
                if (("~all" not in record.to_text() and "-all" not in record.to_text()) and "redirect=" not in record.to_text()):
                    print(f"{GREEN} [-] {domain} SPF record lacks either ~all or -all{ENDC}")
                    print(record.to_text())
                    print(f"\t{RED}Send-MailMessage -SmtpServer <TODO> -To <TODO> -From test@{domain} -Subject 'Test' -Body 'Test'{ENDC}")
                    print("")
                    return True
        if not spfRecordExists:
            print(f"{GREEN} [-] {domain} SPF record does not exist{ENDC}")
            print(f"\t{RED}Send-MailMessage -SmtpServer <TODO> -To <TODO> -From test@{domain} -Subject 'Test' -Body 'Test' -BodyAsHtml{ENDC}")
            print("")
            return True
        return False
    except:
        return False

def check_dmarc(domain):
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarcRecordExists = False
        for record in dmarc_records:
            if "v=DMARC1" in record.to_text():
                dmarcRecordExists = True
                if ((" p=none" in record.to_text() or "\"p=none" in record.to_text() or ";p=none" in record.to_text()) or (" p=" not in record.to_text() and "\"p=" not in record.to_text() and ";p=" not in record.to_text())):
                    print(f"{GREEN} [-] {domain} DMARC policy is set to p=none or no p= value found{ENDC}")
                    print(record.to_text())
                    print(f"\t{RED}Send-MailMessage -SmtpServer <TODO> -To <TODO> -From test@{domain} -Subject 'Test' -Body 'Test' -BodyAsHtml{ENDC}")
                    print("")
                    return True
            if not dmarcRecordExists:
                print(f"{GREEN} [-] {domain} DMARC policy is nonexistent{ENDC}")
                print(f"\t{RED}Send-MailMessage -SmtpServer <TODO> -To <TODO> -From test@{domain} -Subject 'Test' -Body 'Test' -BodyAsHtml{ENDC}")
                print("")
                return True
        return False
    except:
        return False


def main():
    if len(argv) != 2:
        print("Usage: python3 mailfail.py <domain>")
        return
    domain = argv[1]
    spf_result = check_spf(domain)
    dmarc_result = check_dmarc(domain)
        

if __name__ == "__main__":
    main()

