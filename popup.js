// Direct send
// Lack of an SPF or DMARC record
// SPF record never specifies ~all or -all
// SPF with /16 ipv4 mecahnism, a, mx, ptr,exists, include
// DMARC policy is set to p=none or is nonexistent
// Mail Channels without domain lockdown
// Domain Doesnt exist SPF
// domain doesnt exist MX
// check if mail relaying is enabled
// DKIM < 512 bit RSA Key
// extract domains from DAMRC rua= field and check them
// add a link to register the domain

// These are my requirements for its functionality
// - The addon should run when the icon is clicked
// - the domain of the current page and the root domain (if different) should be extracted and used to do DNS record lookups using `https://cloudflare-dns.com/dns-query`
// - The extension will present sections for each type of record lookup (MX, SPF, DMARC) 
// - The extension will help researchers identify the following security misconfigurations
// - when you click on the header for the DNS record it brings you to 

// For SPF records
// - highlight all occurances of ["+all", "?all"] in red
// - highlight all occurances of ["redirect=", "exp=", "exists:"] in blue
// - highlight all occurences of ["-all", "~all"] in green
// - If no SPF record exists for the domain add a list item that states `No SPF Record Found. Email Spoofing is Possible.`
// - if the SPF record doesn't start with "v=spf1" add a list item that states "The SPF record did not start with 'v=spf1' which means it is invalid and spoofing is possible."
// - extract the domains from the include: and redirect= parts of the SPF record and use rdap.net to check if they have been registered. If they haven't been add a new list item that states `SPF Domain(s) Available to Purchase! [ ${availableDomains.join(", ")} ]` The code I wrote for this works well so you wont have to modify it too much
// - if the spf record doesn't include ~all and -all add a list item that says "Neither ~all or -all was found which means spoofing is possible."

// For DMARC
// - highlight all occurances of ["sp=none", "p=none"] in red
// - highlight all occurences of ["p=reject", "p=quarantine"] in green
// - If no DMARC record exists for the domain add a list item that states `No DMARC Record Found. Email Spoofing is Possible.`
// - if the DMARC record includes pct= and it is not set to pct=100, highlight it in red
// - if the DMARC record includes a p= policy which is no-standard ["p=none","p=quarantine","p=reject"] highlight it in red
// - if the DMARC record is missing p= add a list item that states spoofing is possible. sp is for subdomains and p is the policy for the root domain

// For MX
// - if the record includes "mail.protection.outlook.com" then add a new list item that states `Send-MailMessage -SmtpServer ${SMTPServer} -To Victim@${domainName} -From informationsecurity@${domainName} -Subject “Test” -Body “Test” -BodyAsHTML -DeliveryNotificationOption Never -Priority High`


let badge = 0;
browser.runtime.sendMessage({
    action: "updateBadge",
    number: ""
});

document.addEventListener('DOMContentLoaded', function() {
    function getCurrentTabUrl(callback) {
        browser.tabs.query({
            active: true,
            currentWindow: true
        }, function(tabs) {
            const tab = tabs[0];
            const url = tab.url;
            callback(url);
        });
    }

    function notifyDomainAvailable() {
        browser.notifications.create("domain-notification", {
            "type": "basic",
            "iconUrl": browser.runtime.getURL("icons/mailfail-128x128.png"),
            "title": "Serious SPF Misconfiguration Found",
            "message": "The SPF record included reference to an authoritative domain that you can purchase and spoof valid emails from"
        });
    }

    function incrementBadgeForCurrentTab() {
        badge += 1;
        browser.runtime.sendMessage({
            action: "updateBadge",
            number: badge
        });
    }


    async function fetchDomainInfo(domainName) {
        const apiUrl = `https://rdap.net/domain/${domainName}`;
        try {
            const response = await fetch(apiUrl, {
                credentials: 'omit',
                headers: {
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.5',
                },
                method: 'GET',
                redirect: 'follow', // Follow redirects automatically
                mode: 'cors'
            });

            if (response.status === 200) {
                return false; // The domain can not be registered
            } else if (response.status === 404) {
                return true; // The domain can be registered
            } else {
                console.error('Error fetching domain info');
                throw new Error(`Network response for ${domainName} was not ok`, response.status);
            }
        } catch (error) {
            console.error('Error fetching domain info:', error);
            throw error; // Rethrow the error to be caught by the caller
        }
    }

    async function checkSPFDomainAvailable(DNSRecord) {
        const includeRegex = /include:([^ ]+)/g;
        const redirectRegex = /redirect=([^ ]+)/g;
        const spfDomains = [];

        let match;
        while ((match = includeRegex.exec(DNSRecord)) !== null) {
            spfDomains.push(getRootDomain(match[1])); // Push the matched domain into the array
        }

        while ((match = redirectRegex.exec(DNSRecord)) !== null) {
            spfDomains.push(getRootDomain(match[1])); // Push the matched domain into the array
        }

        const uniqueSPFDomains = Array.from(new Set(spfDomains)); // Get unique SPF domains
        const availabilityResults = await Promise.all(uniqueSPFDomains.map(fetchDomainInfo)); // Fetch availability for each domain

        const availableDomains = [];
        availabilityResults.forEach((availability, index) => {
            if (availability) {
                availableDomains.push(uniqueSPFDomains[index]); // Push available domain into the array
            }
        });

        return [availableDomains, uniqueSPFDomains]; // Return array of available domains
    }
    

    function highlightSubstrings(DNSRecordList, redArray, blueArray, greenArray, eachRecord) {
        let highlightedRecord = eachRecord;

        const replaceWithColor = (substring, color) => `<span style="color: ${color};">${substring}</span>`;

        redArray.forEach(substring => {
            if (substring) {
                highlightedRecord = highlightedRecord.replace(new RegExp(escapeRegExp(substring), 'g'), match => replaceWithColor(match, 'red'));
            }
        });

        blueArray.forEach(substring => {
            if (substring) {
                highlightedRecord = highlightedRecord.replace(new RegExp(escapeRegExp(substring), 'g'), match => replaceWithColor(match, 'blue'));
            }
        });

        greenArray.forEach(substring => {
            if (substring) {
                highlightedRecord = highlightedRecord.replace(new RegExp(escapeRegExp(substring), 'g'), match => replaceWithColor(match, 'green'));
            }
        });

        addItemToDNSRecordList(highlightedRecord, DNSRecordList);
    }

    function addItemToDNSRecordList(text, DNSRecordList) {
        const DNSRecord = document.createElement('li');
        DNSRecord.style.fontWeight = 'bold';
        DNSRecord.innerHTML = text;
        DNSRecordList.appendChild(DNSRecord);
    }


    function createHeader(PopUpDiv, domainName, headerText){
        const domainLink = document.createElement('a');
        domainLink.href = `https://mxtoolbox.com/emailhealth/${domainName}/`;
        domainLink.innerHTML = `<h2>${domainName} ${headerText}:</h2>`;
        domainLink.style.textDecoration = 'none'
        domainLink.style.fontWeight = 'bold';
        PopUpDiv.appendChild(domainLink);
    }

    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
    }

    function checkRecord(apiUrl, domainName, headerText) {
        let SPFExists = false;
        let DMARCExists = false;
        fetch(apiUrl, {
                headers: {
                    'Accept': 'application/dns-json'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Network response for ${headerText} was not ok`);
                }
                return response.json();
            })
            .then(JSONData => {
                const RED = `<span style="color: red;">`;
                const END = `</span>`;
                const container = document.querySelector('.container');
                const PopUpDiv = document.createElement('div');
                createHeader(PopUpDiv, domainName, headerText);
                const DNSRecordList = document.createElement('ul');

                // If the DNS record has no results
                if (!JSONData.Answer || JSONData.Answer.length === 0) {
                    if (headerText === "DMARC") {
                        incrementBadgeForCurrentTab();
                        addItemToDNSRecordList(`${RED}No ${headerText} Record Found. Email Spoofing is Possible.${END}`, DNSRecordList);
                    } else if (headerText === "MX") {
                        addItemToDNSRecordList(`No ${headerText} Record Found. This domain can't recieve Emails.`, DNSRecordList);
                    }
                } else {
                    JSONData.Answer.forEach(async (record) => {
                        let eachRecord = record.data.replace(/^\"|\"$/g, ''); // Remove leading and trailing quotes
                        if (headerText === "SPF") {
                            if (eachRecord.includes("v=spf1") && !eachRecord.startsWith("v=spf1")) {
                                SPFExists = true;
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}The SPF record did not start with 'v=spf1'. Email spoofing is possible.${END}`, DNSRecordList);
                            } else if (eachRecord.includes("v=spf1")) {
                                SPFExists = true;
                                let red = ["+all", "?all"];
                                let blue = ["redirect=", "exp=", "exists:", " mx ", " a ", " ptr ", " +mx ", " +a "];
                                let green = ["-all", "~all"];
                                highlightSubstrings(DNSRecordList, red, blue, green, eachRecord);

                                if (!eachRecord.includes("~all") && !eachRecord.includes("-all")) {
                                    incrementBadgeForCurrentTab();
                                    addItemToDNSRecordList(`${RED}Neither ~all or -all was found. Email spoofing is possible.${END}`, DNSRecordList);
                                }
                                await checkSPFDomainAvailable(eachRecord)
                                    .then(([availableDomains, spfDomains]) => {
                                        if (availableDomains.length > 0) {
                                            addItemToDNSRecordList(`An SPF Domain is Available to Purchase! ${RED}[ ${availableDomains.join(", ")} ]${END}`, DNSRecordList);
                                            incrementBadgeForCurrentTab();
                                            notifyDomainAvailable();
                                        } else {
                                            addItemToDNSRecordList(`No SPF Domains Available to Purchase [ ${spfDomains.join(", ")} ]`, DNSRecordList);
                                        }
                                    });
                            }
                        }
                        if (headerText === "DMARC" && eachRecord.includes("v=DMARC1")) {
                            DMARCExists = true;
                            let red = ["sp=none", "p=none", "fo=0"];
                            let blue = ["aspf=r", "adkim=r"];
                            let green = ["sp=reject", "sp=quarantine", "p=reject", "p=quarantine", "rua=", "ruf=", "adkim=s", "aspf=s", "pct=100"];
                            
                            if (!eachRecord.startsWith("v=DMARC1")) {
                                red.push("v=DMARC1");
                                incrementBadgeForCurrentTab();
                            }if (eachRecord.includes("pct=") && !eachRecord.includes("pct=100")) {
                                red.push("pct=");
                                incrementBadgeForCurrentTab();
                            }
                            highlightSubstrings(DNSRecordList, red, blue, green, eachRecord);
                            if (!eachRecord.includes("p=quarantine") && !eachRecord.includes("p=reject")) {
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}Neither p=quarantine or p=reject was found. Email spoofing is possible.${END}`, DNSRecordList);
                            } if (!eachRecord.includes("p=")) {
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}A Domain Policy p= is Missing. Email spoofing is possible.${END}`, DNSRecordList);
                            }
                        }
                        if (headerText === "MX") {
                            if (!eachRecord.includes("mail.protection.outlook.com") && eachRecord !== "") {
                                if (eachRecord.includes(' ')) {
                                    addItemToDNSRecordList(eachRecord.split(' ')[1], DNSRecordList);
                                } else {
                                    addItemToDNSRecordList(eachRecord, DNSRecordList);
                                }
                            } else if (eachRecord.includes("mail.protection.outlook.com")) {
                                let SMTPServer = eachRecord.split(' ')[1];
                                addItemToDNSRecordList(SMTPServer, DNSRecordList);
                                addItemToDNSRecordList(`${RED}Send-MailMessage -SmtpServer ${SMTPServer} -To Victim@${domainName} -From informationsecurity@${domainName} -Subject “Test” -Body “Test” -BodyAsHTML -DeliveryNotificationOption Never -Priority High${END}`, DNSRecordList);
                                incrementBadgeForCurrentTab();
                            }
                        }
                    });
                }

                if (headerText === "SPF" && !SPFExists) {
                    addItemToDNSRecordList(`${RED}No SPF Record Found. Email Spoofing is Possible.${END}`, DNSRecordList);
                    incrementBadgeForCurrentTab();
                }

                PopUpDiv.appendChild(DNSRecordList);
                container.appendChild(PopUpDiv);

            })
            .catch(error => {
                console.error(`Error fetching ${headerText} results:`, error);
            });
    }

    function fetchMailCheckResults(domainName, rootDomain) {
        const apiUrlTXT = `https://cloudflare-dns.com/dns-query?name=${domainName}&type=TXT`;
        const apiUrlMX = `https://cloudflare-dns.com/dns-query?name=${domainName}&type=MX`;
        const apiUrlDMARC = `https://cloudflare-dns.com/dns-query?name=_dmarc.${domainName}&type=TXT`;


        checkRecord(apiUrlMX, domainName, 'MX');
        checkRecord(apiUrlTXT, domainName, 'SPF');
        checkRecord(apiUrlDMARC, domainName, 'DMARC');

        if (domainName !== rootDomain) {
            const apiUrlTXTRoot = `https://cloudflare-dns.com/dns-query?name=${rootDomain}&type=TXT`;
            const apiUrlMXRoot = `https://cloudflare-dns.com/dns-query?name=${rootDomain}&type=MX`;
            const apiUrlDMARCRoot = `https://cloudflare-dns.com/dns-query?name=_dmarc.${rootDomain}&type=TXT`;
            checkRecord(apiUrlMXRoot, rootDomain, 'MX');
            checkRecord(apiUrlTXTRoot, rootDomain, 'SPF');
            checkRecord(apiUrlDMARCRoot, rootDomain, 'DMARC');
        }
    }

    function getRootDomain(url) {
        // Remove double quotes and single quotes from the URL
        url = url.replace(/["']/g, '');

        const temp = url.split('.').reverse();
        return temp[1] + '.' + temp[0];
    }

    getCurrentTabUrl(function(url) {
        const domainName = (new URL(url)).hostname;
        const rootDomain = getRootDomain((new URL(url)).hostname);

        var hunterLink = document.getElementById("hunterlink");
        hunterLink.href = `https://hunter.io/try/search/${rootDomain}?locale=en`; 
        var hunterLink = document.getElementById("dnsquerieslink");
        hunterLink.href = `https://www.dnsqueries.com/en/smtp_test_check.php`; 
       
        fetchMailCheckResults(domainName, rootDomain);
    });
});
