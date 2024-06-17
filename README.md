# MailFail

MailFail identifies and provides commands to exploit a large number of email-related misconfigurations for the current domain and subdomain. The extensions UI popup highlights any misconfigurations in red and links to the supporting documentation.

Ontop of the checks done by the extension, listed below, each section header includes a link to a resource which autofills the domain and runs checks.

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
