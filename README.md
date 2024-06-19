# MailFail
[<img src="https://blog.mozilla.org/addons/files/2020/04/get-the-addon-fx-apr-2020.svg" alt="for Firefox" height="60px">](https://addons.mozilla.org/en-US/firefox/addon/mailfail)

[![Firefox Rating](https://img.shields.io/amo/stars/css-exfil-protection.svg?label=Rating&style=for-the-badge)](https://addons.mozilla.org/en-US/firefox/addon/mailfail)
![Mozilla Add-on](https://img.shields.io/amo/v/mailfail?label=Latest%20Version&style=for-the-badge)

MailFail identifies and provides commands to exploit a large number of email-related misconfigurations for the current domain and subdomain within a web browser. The extension's UI popup highlights any misconfigurations in red and links to the supporting documentation.
# Popup
<p align="center">
  <img src="https://github.com/ACK-J/MailFail/assets/60232273/e50189f7-16bc-4664-824e-3e9ac0c5ac34" alt="GUI">
</p>

Ontop of the checks done by the extension, listed below, each section header includes a link to a resource which autofills the domain and runs checks. Aditionally, the four logos at the to of the popup are especially helpful and provide the following functions (from left to right):
- Checks if the MX domain can be used as an open relay
- Links to hunter.io which finds email addresses used by the domain
- Uses MXToolbox to run a "domain health" report
- Checks if the MX domain will send an unauthenticated email internally

# Example Misconfigurations
| | | |
|:-------------------------:|:-------------------------:|:-------------------------:|
| <img width="287" alt="DKIM" src="https://github.com/ACK-J/MailFail/assets/60232273/3e0267b3-94fb-4475-9b89-07fe205b96ba"></br>A DKIM selector uses a weak RSA key that can be cracked and used to sign spoofed emails.|<img width="287" alt="NSA" src="https://github.com/ACK-J/MailFail/assets/60232273/c035d56c-2849-440b-8636-4f2061a489f7"></br>A weak DNSKEY algorithm is used.|<img width="287" alt="GUI" src="https://github.com/ACK-J/MailFail/assets/60232273/ad564472-7dab-40ab-b31a-5dd270c50da7"></br>The zone file was enumerated including potentially hidden DKIM and ARC selectors. |

# What Misconfigurations are Checked?
### SPF
- Does the record start with v=spf1?
- Do the IPv4 address ranges specified include an SMTP open relay?
- Does the record not include a catch all mechanism but does include a redirect?
- Does the record include ?all or +all which doesn't enforce SPF?
- Does the record defer to a redirect?
- Does the record use -all (hardfail) which isn't recommended?
- Does the record use the PTR mechanims which is marked as "DO NOT USE" in the RFC?
- Does the record use MailChannels and have "Domain Lockdown" configured?
- Does the record use multiple pairs of double quotes which can have consequences?
- Are the domains referenced within the record available to purchase?
- Is a _spf record used which is no longer supported?
- Does the domain and subdomain have an SPF record?
- Is there more than one SPF recrod?
### DMARC
- Is the pct= lower than 100?
- Does the record start with v=DMARC1?
- Is the policy set to quarantine or reject?
- Is the policy missing?
- Is the subdomain policy set to none?
- Is fo=1 but ruf= is missing/present?
- Is rua= or ruf= malformed?
- If the pct= is lower than 100 the policy enforced is reduced.
- If the pct= is lower than 100 the subdomain policy enforced is reduced.
- Are the domains referenced within the record available to purcahse?
- Does the subdomain policy default to the root policy?
- OSINT link to DMARC.live.
- Is a CNAME used by DMARC?
- Can the domain and subdomain emails be spoofed?
- Is there more than one DMARC record?
- Are the domains specifed in RUA and RUF configured correctly to receive emails?
- Are the domains specifed in RUA and RUF configured to receive DMARC reports from any website?
### DKIM
- Brute force common DKIM selectors.
- Does the record use a short key length? (<1024)
- Can the private key be cracked?
- What is the base-10 public key modulus?
- Does the record start with v=DKIM1?
### ARC
- Brute force common ARC selectors.
- Does the record use a short key length? (<1024)
- Can the private key be cracked?
### BIMI
- Does a BIMI record exist?
- Does the record start with v=BIMI1?
- Does the record use an SVG image?
- If the record includes a certificate, parse the metadata.
### MX
- If the record points to outlook, is Microsoft direct send enabled externally?
- Is the record valid?
### MTA-STS
- Does the record start with v=STSv1?
- Is the well known MTA-STS file in testing mode?
- Does the MTA-STS file have an active policy?
### DANE
- Is DANE used for SMTP?
- A command is provided to verify the correctness of each record.
- Is the usage flag incorectly set for SMTP?
- Is the selector flag incorrectly set for SMTP?
- Is the Matching-type flag incorrectly set for SMTP?
- Is the record valid?
### DNSSEC
- Is DNSSEC used?
- Is each record a zone-signing key or a secure entry point?
- What algorithm is used and is it secure?
- Is the protocol field set to 3?
### SMTP TLS Reporting
- Does the record start with v=TLSRPTv1?
- Does the record use HTTP instead of HTTPS?
### ADSP
- Is an ADSP record available? This protocol is considered "dead" and has been superseded by DMARC.
### Mail Channels
- Is a MailChannels record found?
- Is it configured to use CloudFlare workers?
### NSEC
- Is NSEC used by DNSSEC?
- Can you NSEC-walk the zone file?
- Are "black lies" used?
- Commands are provided to NSEC-walk locally.
### NSEC3
- Is NSEC3 used by DNSSEC?
- Return a subset of the NSEC3 hashes.
- Provide the commands to extract all NSEC3 hashes locally.
- Which hashing algorithm is used?
- Which salt is used?
### SRV
- Does the server adverstise IMAP, POP, or SMTP services?

## Donations ❤️
If you are feeling generous or really like my work, consider donating
- Monero Address: `89jYJvX3CaFNv1T6mhg69wK5dMQJSF3aG2AYRNU1ZSo6WbccGtJN7TNMAf39vrmKNR6zXUKxJVABggR4a8cZDGST11Q4yS8`

## Permissions Needed
**Display notifications to you**
- This is needed so the addon can alert you when a severe misconfiguration is discovered.
**Access browser tabs**
- This is needed so the addon can display the proper number of misconfigurations on a per-tab basis.
