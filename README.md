# MailFail

Firefox extension that checks for flaws in the email security of the current domain 

## What does this addon do?
1. Direct send
1. Lack of an SPF or DMARC record
1. SPF record never specifies ~all or -all
1. SPF with /16 ipv4 mechanism, a, mx, ptr, exists, include
1. DMARC policy is set to p=none or is nonexistent
1. Mail Channels without domain lockdown
1. Domain doesn't exist SPF
1. Domain doesn't exist MX
1. Check if mail relaying is enabled
1. DKIM < 512 bit RSA Key
1. Extract domains from DMARC rua= field and check them
1. Add a link to register the domain

## Donations ❤️
If you are feeling generous or really like my work, consider donating
- Monero Address: `89jYJvX3CaFNv1T6mhg69wK5dMQJSF3aG2AYRNU1ZSo6WbccGtJN7TNMAf39vrmKNR6zXUKxJVABggR4a8cZDGST11Q4yS8`

## Permissions Needed
**Display notifications to you**
- This is needed so the addon can alert you when a domain is available to register and used in an SPF record.

# ToDo:

