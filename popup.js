

let badge = 0;
browser.runtime.sendMessage({
    action: "updateBadge",
    number: ""
}); 
// Global variable to check if the root domain's dmarc policy is set to reject. This is important for subdomains
let DMARCSubDomainSpoofable = true;

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
            spfDomains.push(getRootDomain(match[1]));
        }
    
        while ((match = redirectRegex.exec(DNSRecord)) !== null) {
            spfDomains.push(getRootDomain(match[1]));
        }
    
        const uniqueSPFDomains = Array.from(new Set(spfDomains)); // Get unique SPF domains
        const availabilityResults = await Promise.all(uniqueSPFDomains.map(fetchDomainInfo)); // Fetch availability for each domain
    
        const availableDomains = [];
        availabilityResults.forEach((availability, index) => {
            if (availability) {
                availableDomains.push(uniqueSPFDomains[index]); // Push available domain into the array
            }
        });
    
        // Encode HTML entities for availableDomains and uniqueSPFDomains
        const encodedAvailableDomains = availableDomains.map(encodeHtmlEntities);
        const encodedUniqueSPFDomains = uniqueSPFDomains.map(encodeHtmlEntities);
    
        return [encodedAvailableDomains, encodedUniqueSPFDomains]; // Return array of available domains
    }
    

    function highlightSubstrings(DNSRecordList, redArray, blueArray, greenArray, eachRecord) {
        let highlightedRecord = eachRecord;
    
        const replaceWithColor = (substring, color) => {
            // Check if the substring starts and ends with a space
            const startsWithSpace = /^\s/.test(substring);
            const endsWithSpace = /\s$/.test(substring);
        
            // Add spaces around the substring if necessary
            if (startsWithSpace && endsWithSpace) {
                return ` <span style="color: ${color};">${substring}</span> `;
            } else {
                return `<span style="color: ${color};">${substring}</span>`;
            }
        };
        
    
        // Function to escape regular expression special characters
        const escapeRegExp = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
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
    
    // Replaces (<, >, &, ', ", and characters in the range \u00A0 to \u9999) with their respective HTML entity representations
    function encodeHtmlEntities(str) {
        return str.replace(/[\u00A0-\u9999<>&'"]/gim, function(i) {
            return '&#' + i.charCodeAt(0) + ';';
        });
    }    

    function addItemToDNSRecordList(text, DNSRecordList) {
        const DNSRecord = document.createElement('li');
        DNSRecord.style.fontWeight = 'bold';
        DNSRecord.innerHTML = text; // Dynamic Values are HTML Entities Encoded
        DNSRecordList.appendChild(DNSRecord);
    }

    function createHeader(PopUpDiv, domainName, headerText, link){
        const domainLink = document.createElement('a');
        domainLink.href = link;
        domainLink.innerHTML = `<h2>${domainName} ${headerText}:</h2>`; // Dynamic Values are HTML Entities Encoded
        domainLink.style.textDecoration = 'none'
        domainLink.style.fontWeight = 'bold';
        PopUpDiv.appendChild(domainLink);
    }

    function checkRecord(apiUrl, domainName, headerText) {
        let SPFExists = false;
        let DMARCExists = false;
        let DMARCCount = 0;
        const isSubDomain = domainName.split(".").length > 2; // If there's more than one period, there will be at least 2 elements in the array
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
                if (headerText === "SPF") {
                    createHeader(PopUpDiv, domainName, headerText, `https://dmarcian.com/spf-survey/?domain=${domainName}`);
                } else if (headerText === "DMARC") {
                    createHeader(PopUpDiv, domainName, headerText, `https://dmarcian.com/dmarc-inspector/?domain=${domainName}`);
                } else if (headerText === "MX") {
                    createHeader(PopUpDiv, domainName, headerText, `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${domainName}&run=toolpage`);
                }
                
                const DNSRecordList = document.createElement('ul');

                // If the DNS record has no results
                if (!JSONData.Answer || JSONData.Answer.length === 0) {
                    if (headerText === "MX") {
                        addItemToDNSRecordList(`No ${headerText} Record Found. This Domain can't Recieve Emails.`, DNSRecordList);
                    }
                }  else {
                    JSONData.Answer.forEach(async (record) => {
                        let eachRecord = encodeHtmlEntities(record.data.replace(/^\"|\"$/g, '')); // Remove leading and trailing quotes
                        if (headerText === "SPF") {
                            if (eachRecord.includes("v=spf1") && !eachRecord.startsWith("v=spf1")) {
                                SPFExists = true;
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}The SPF record did not start with 'v=spf1'. The Record is Invalid and Email Spoofing is Possible.${END}`, DNSRecordList);
                            } else if (eachRecord.includes("v=spf1")) {
                                SPFExists = true;
                                let red = ["+all", "?all"];
                                let blue = ["redirect=", "exp=", "exists:", " a ", " mx ", " ptr ", " +mx ", " +a ", "+ptr", "/16", "/8"];
                                let green = ["-all", "~all"];
                                highlightSubstrings(DNSRecordList, red, blue, green, eachRecord);

                                if (!eachRecord.includes("~all") && !eachRecord.includes("-all")) {
                                    incrementBadgeForCurrentTab();
                                    addItemToDNSRecordList(`${RED}Neither ~all or -all was Found. Email Spoofing is Possible.${END}`, DNSRecordList);
                                }
                                await checkSPFDomainAvailable(eachRecord)
                                    .then(([availableDomains, spfDomains]) => {
                                        if (availableDomains.length > 0) {
                                            addItemToDNSRecordList(`One or More of the SPF Domain(s) are Available to Purchase! ${RED}[ ${availableDomains.join(", ")} ]${END}`, DNSRecordList);
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
                            DMARCCount += 1;
                            let red = ["sp=none", "p=none", "fo=0", "fo=d"];
                            let blue = ["aspf=r", "adkim=r"];
                            let green = ["sp=reject", "sp=quarantine", "p=reject", "p=quarantine", "rua=", "ruf=", "adkim=s", "aspf=s", "pct=100", "fo=1"];
                            
                            if (!eachRecord.startsWith("v=DMARC1")) {
                                red.push("v=DMARC1");
                                incrementBadgeForCurrentTab();
                            }if (eachRecord.includes("pct=") && !eachRecord.includes("pct=100")) {
                                red.push("pct=");
                                incrementBadgeForCurrentTab();
                            }
                            highlightSubstrings(DNSRecordList, red, blue, green, eachRecord);
                            if (eachRecord.includes("pct=") && !eachRecord.includes("pct=100")) {
                                addItemToDNSRecordList(`${RED}The pct= Tag was not Set to 100. Email Spoofing is Possible.${END}`, DNSRecordList);
                            } if (!eachRecord.includes("p=quarantine") && !eachRecord.includes("p=reject")) {
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}Neither p=quarantine or p=reject was found. Email Spoofing is Possible.${END}`, DNSRecordList);
                            } if (!eachRecord.includes("p=")) {
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}A Domain Policy (p=) is Missing. Email Spoofing is Possible.${END}`, DNSRecordList);
                            } if (eachRecord.includes("fo=1") && !eachRecord.includes("ruf=")) {
                                incrementBadgeForCurrentTab();
                                addItemToDNSRecordList(`${RED}Forensic Reporting Enabled Without a Delivery Address (ruf=). No DMARC Reports are Sent.${END}`, DNSRecordList);
                            } if (!eachRecord.includes("fo=1") && eachRecord.includes("ruf=")) {
                                addItemToDNSRecordList(`Forensic Address Specified (ruf=) Without Forensic Reports Enabled (fo=1). DMARC Reports are Sent only if All Underlying Authentication Mechanisms Fail.`, DNSRecordList);
                            } if (!isSubDomain){ // if root domain
                                if (eachRecord.includes("sp=none")){
                                    DMARCSubDomainSpoofable = true;
                                } else if (!eachRecord.includes("sp=") && eachRecord.includes("p=none")){
                                    DMARCSubDomainSpoofable = true;
                                } else if (eachRecord.includes("sp=none") && eachRecord.includes("p=none")){
                                    DMARCSubDomainSpoofable = true;
                                } else if (!eachRecord.includes("sp=") && !eachRecord.includes("p=")){
                                    DMARCSubDomainSpoofable = true;
                                } else {
                                    DMARCSubDomainSpoofable = false;
                                }
                            } 
                            
                        }
                        if (headerText === "MX") {
                            if (!eachRecord.includes("mail.protection.outlook.com") && !eachRecord.includes("mail.protection.partner.outlook.cn") && eachRecord !== "") {
                                if (eachRecord.includes(' ')) { // Check for priority in MX record "50 mail.example.com" 
                                    addItemToDNSRecordList(eachRecord.split(' ')[1], DNSRecordList);
                                } else {
                                    addItemToDNSRecordList(eachRecord, DNSRecordList);
                                }
                            } else if (eachRecord.includes("mail.protection.outlook.com") || eachRecord.includes("mail.protection.partner.outlook.cn")) {
                                let SMTPServer = eachRecord.split(' ')[1];
                                // Removes the warning banner added to suspicious emails in Outlook
                                const hideWarningBanner = "&lt;style&gt;table,tr{width:1px;height:1px;display:none;}&lt;/style&gt;"
                                addItemToDNSRecordList(SMTPServer, DNSRecordList);
                                addItemToDNSRecordList(`${RED}Send-MailMessage -SmtpServer ${SMTPServer} -To Victim@${domainName} -From informationsecurity@${domainName} -Subject “Test” -Body “${hideWarningBanner}Test” -BodyAsHTML -DeliveryNotificationOption Never -Priority High -UseSsl${END}`, DNSRecordList);
                                incrementBadgeForCurrentTab();
                            }
                        }
                    });
                }

                if (headerText === "SPF" && !SPFExists) {
                    addItemToDNSRecordList(`${RED}No SPF Record Found. Email Spoofing is Possible.${END}`, DNSRecordList);
                    incrementBadgeForCurrentTab();
                }
                if (isSubDomain && !DMARCSubDomainSpoofable && DMARCCount === 0 && headerText === "DMARC") {
                    addItemToDNSRecordList(`No Subdomain DMARC Record Found. The Root Domain DMARC Policy is Applied.`, DNSRecordList);
                } else if (DMARCCount === 0 && headerText === "DMARC") {
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`${RED}No DMARC Record Found or Root Domain was Misconfigured. Email Spoofing is Possible.${END}`, DNSRecordList);
                }
                // If there are more than one valid DMARC records then DMARC discovery will fail
                if (DMARCCount > 1 && headerText === "DMARC"){
                    incrementBadgeForCurrentTab();
                    const rfc7489_6_6_3= `<a href="https://datatracker.ietf.org/doc/html/rfc7489#section-6.6.3"><img src=icons/info.jpg style=width:20px;height:20px;></a>`
                    addItemToDNSRecordList(`${rfc7489_6_6_3} ${RED}Multiple DMARC Records Found. Email Spoofing is Possible.${END}`, DNSRecordList);
                } 

                PopUpDiv.appendChild(DNSRecordList);
                container.appendChild(PopUpDiv);

            })
            .catch(error => {
                console.error(`Error fetching ${headerText} results:`, error);
            });
    }

    function fetchMailCheckResults(domainName, rootDomain) {
        // Check Root Domain
        const apiUrlTXT = `https://cloudflare-dns.com/dns-query?name=${domainName}&type=TXT`;
        const apiUrlMX = `https://cloudflare-dns.com/dns-query?name=${domainName}&type=MX`;
        const apiUrlDMARC = `https://cloudflare-dns.com/dns-query?name=_dmarc.${domainName}&type=TXT`;
        checkRecord(apiUrlMX, domainName, 'MX');
        checkRecord(apiUrlTXT, domainName, 'SPF');
        checkRecord(apiUrlDMARC, domainName, 'DMARC');
        // Check Subdomain
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
        const hostname = (new URL(url)).hostname
        if (hostname !== ""){
            const domainName = encodeHtmlEntities(hostname);
            const rootDomain = encodeHtmlEntities(getRootDomain(hostname));
    
            // Update UI Links
            document.getElementById("hunterlink").href = `https://hunter.io/try/search/${rootDomain}?locale=en`; 
            document.getElementById("dnsquerieslink").href = `https://www.dnsqueries.com/en/smtp_test_check.php`; 
            document.getElementById("mxlink").href = `https://mxtoolbox.com/emailhealth/${rootDomain}/`; 
           
            fetchMailCheckResults(domainName, rootDomain);
        } else{
            const container = document.querySelector('.container');
            const PopUpDiv = document.createElement('div');
            createHeader(PopUpDiv, hostname, "Domain is Not Valid", `#`);
            container.appendChild(PopUpDiv);
        }
    });
});
