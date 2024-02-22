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

// FP: https://www.fotor.com/photo-editor-app/editor/basic/basicResize
// FP: https://app.mavenlink.com/login?from_redirect=true
// Logo https://www.vectorstock.com/royalty-free-vector/sad-work-email-icon-outline-style-vector-36359119
// Resize https://hotpot.ai/icon-resizer

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

    function checkSPF(record, mechanism) {
        return record.includes(mechanism);
    }

    function checkDMARCNone(record) {
        return record.includes("p=none");
    }

    function checkDMARCPolicyExists(record) {
        return !record.includes("p=");
    }
    
    function checkDMARCPolicyStandard(record) {
        return record.includes("p=") && !record.includes("p=none") && !record.includes("p=reject") && !record.includes("p=quarantine");
    }
    
    function checkDMARCPercent(record) {
        return record.includes("pct=") && !record.includes("pct=100");
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
    

    function highlightSubstrings(DNSRecord, redArray, blueArray, greenArray, eachRecord) {
        let highlightedRecord = eachRecord;
        DNSRecord.style.fontWeight = 'bold';

        const replaceWithColor = (substring, color) => `<span style="color: ${color};">${substring}</span>`;

        redArray.forEach(substring => {
            if (substring) {
                highlightedRecord = highlightedRecord.replace(new RegExp(substring, 'g'), match => replaceWithColor(match, 'red'));
            }
        });

        blueArray.forEach(substring => {
            if (substring) {
                highlightedRecord = highlightedRecord.replace(new RegExp(substring, 'g'), match => replaceWithColor(match, 'blue'));
            }
        });

        greenArray.forEach(substring => {
            if (substring) {
                highlightedRecord = highlightedRecord.replace(new RegExp(substring, 'g'), match => replaceWithColor(match, 'green'));
            }
        });

        DNSRecord.innerHTML = highlightedRecord;
    }

    function addItemToDNSRecordList(text, DNSRecordList) {
        const DNSRecord = document.createElement('li');
        DNSRecord.style.fontWeight = 'bold';
        DNSRecord.innerHTML = text;
    }


    function createHeader(PopUpDiv, domainName, headerText){
        const domainLink = document.createElement('a');
        domainLink.href = `https://mxtoolbox.com/emailhealth/${domainName}/`;
        domainLink.innerHTML = `<h2>${domainName} ${headerText}:</h2>`;
        domainLink.style.textDecoration = 'none'
        domainLink.style.fontWeight = 'bold';
        PopUpDiv.appendChild(domainLink);
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
                const container = document.querySelector('.container');
                const PopUpDiv = document.createElement('div');
                createHeader(PopUpDiv, domainName, headerText);
                const DNSRecordList = document.createElement('ul');

                // Create a new list item
                const DNSRecord = document.createElement('li');
                // If the DNS record has no results
                if (!JSONData.Answer || JSONData.Answer.length === 0) {
                    if (headerText === "DMARC") {
                        incrementBadgeForCurrentTab();
                        addItemToDNSRecordList(`<span style="color: red;">No ${headerText} Record Found. Email Spoofing is Possible.</span>`, DNSRecordList);
                    } else if (headerText === "MX") {
                        addItemToDNSRecordList(`No ${headerText} Record Found.`, DNSRecordList);
                    }
                } else {
                    JSONData.Answer.forEach(async (record) => {
                        let eachRecord = record.data.replace(/^\"|\"$/g, ''); // Remove leading and trailing quotes
                        if (headerText === "SPF") {
                            if (eachRecord.includes("v=spf") && !eachRecord.startsWith("v=spf1")) {
                                SPFExists = true;
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList("The SPF record did not start with 'v=spf1' which means it is invalid and spoofing is possible.", DNSRecordList);
                            } else if (eachRecord.includes("v=spf1")) {
                                SPFExists = true;
                                let red = ["+all", "?all"];
                                let blue = ["redirect=", "exp=", "exists:"];
                                let green = ["-all", "~all"];
                                highlightSubstrings(DNSRecord, red, blue, green, eachRecord);

                                if (!eachRecord.includes("~all") && !eachRecord.includes("-all")) {
                                    incrementBadgeForCurrentTab();
                                    addItemToDNSRecordList("Neither ~all or -all was found which means spoofing is possible.", DNSRecordList);
                                }
                                await checkSPFDomainAvailable(eachRecord)
                                    .then(([availableDomains, spfDomains]) => {
                                        if (availableDomains.length > 0) {
                                            addItemToDNSRecordList(`SPF Domain(s) Available to Purchase! [ ${availableDomains.join(", ")} ]`, DNSRecordList);
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
                            let red = ["sp=none", "p=none"];
                            let blue = [];
                            let green = ["p=reject", "p=quarantine"];
                            highlightSubstrings(DNSRecord, red, blue, green, eachRecord);
                            // if (!eachRecord.startsWith("v=DMARC1")) {
                            //     addListItem(DNSRecord, eachRecord, "v=DMARC1", "red");
                            //     incrementBadgeForCurrentTab();
                            // }  if (!checkDMARCNone(eachRecord)) {
                            //     addListItem(DNSRecord, eachRecord, null, "black");
                            // } if (checkDMARCPolicyExists(eachRecord)) {
                            //     addListItem(DNSRecord, eachRecord, null, "red");
                            //     incrementBadgeForCurrentTab();
                            // } if (checkDMARCPolicyStandard(eachRecord)) {
                            //     addListItem(DNSRecord, eachRecord, "p=", "red");
                            //     incrementBadgeForCurrentTab();
                            // } if (checkDMARCPercent(eachRecord)) {
                            //     addListItem(DNSRecord, eachRecord, "pct=", "red");
                            //     incrementBadgeForCurrentTab();
                            // }
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
                                addItemToDNSRecordList(`Send-MailMessage -SmtpServer ${SMTPServer} -To Victim@${domainName} -From informationsecurity@${domainName} -Subject “Test” -Body “Test” -BodyAsHTML -DeliveryNotificationOption Never -Priority High`, DNSRecordList);
                                incrementBadgeForCurrentTab();
                            }
                        }
                    });
                }

                if (headerText === "SPF" && !SPFExists) {
                    addItemToDNSRecordList(`No SPF Record Found. Email Spoofing is Possible.`, DNSRecord);
                    incrementBadgeForCurrentTab();
                }
                // if (headerText === "DMARC" && !DMARCExists) {
                //     addItemToDNSRecordList(`No DMARC Record Found. Email Spoofing is Possible.`, DNSRecord);
                //     incrementBadgeForCurrentTab();
                // }
                DNSRecordList.appendChild(DNSRecord);
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
        hunterLink.href = `https://hunter.io/try/search/${rootDomain}?locale=en`; // Replace "https://example.com" with your desired URL

        fetchMailCheckResults(domainName, rootDomain);
    });
});
