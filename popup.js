// Direct send
// Lack of an SPF or DMARC record
// SPF record never specifies ~all or -all
// SPF with /16 ipv4 mecahnism, a, mx, ptr,exists, include
// DMARC policy is set to p=none or is nonexistent
// Mail Channels without domain lockdown
// Domain Doesnt exist SPF
// domain doesnt exist MX
// check if mail relaying is enabled
// DKIM < 512 and 768 bit RSA keys bit RSA Key
// extract domains from DAMRC rua= field and check them
// add a link to register the domain

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

// For BIMI
// - retrieves the SVG

// For DKIM
// - checks if selectors exist and checks the RSA-bits used
// - 512 or 768 can be cracked 

// For ARC
// - checks if selectors exist and checks the RSA-bits used
// - 512 or 768 can be cracked 



let badge = 0;
browser.runtime.sendMessage({
    action: "updateBadge",
    number: ""
}); 

const DKIMSelectors = ["0xdeadbeef","2005","2006","2007","2008","2009","2010","2011","2012","2013","2014","2015","2016","2017","2018","2019","2020","2021","2022","2023","20230601","2024","512","768","allselector","alpha","amazonses","auth","authsmtp","beta","bfi","ca","care","centralsmtp","class","cm","corp","Corporate","d2005","d2006","d2007","d2008","d2009","d2010","d2011","d2012","d2013","d2014","d2015","d2016","d2017","d2018","d2019","d2020","d2021","d2022","d2023","d2024","default","delta","dk","dk01","dk02","dk03","dk04","dk05","dk06","dk07","dk08","dk09","dk1","dk10","dk1024","dk11","dk12","dk13","dk14","dk15","dk16","dk17","dk18","dk19","dk2","dk20","dk2005","dk20050327","dk2006","dk2007","dk2008","dk2009","dk2010","dk2011","dk2012","dk2013","dk2014","dk2015","dk2016","dk2017","dk2018","dk2019","dk2020","dk2021","dk2022","dk2023","dk2024","dk2048","dk256","dk3","dk384","dk4","dk5","dk512","dk6","dk7","dk768","dk8","dk9","dkim","dkim01","dkim02","dkim03","dkim04","dkim05","dkim06","dkim07","dkim08","dkim09","dkim1","dkim10","dkim1024","dkim11","dkim12","dkim13","dkim14","dkim15","dkim16","dkim17","dkim18","dkim19","dkim2","dkim20","dkim2048","dkim256","dkim3","dkim384","dkim4","dkim5","dkim512","dkim6","dkim7","dkim768","dkim8","dkim9","dkimmail","dkimrnt","dkrnt","dksel","domk","duh","dyn","dynect","eb1","eb10","eb11","eb12","eb13","eb14","eb15","eb16","eb17","eb18","eb19","eb2","eb20","eb3","eb4","eb5","eb6","eb7","eb8","eb9","ebmailerd","ED-DKIM","ei","email0517","emarsys","emarsys1","emarsys2","emarsys3","et","everlytickey1","everlytickey2","exim","exim4u","EXPNSER28042022","facebook","fm1","fm2","fm3","fm4","fm5","fm6","fm7","fm8","fm9","gamma","gears","global","gmmailerd","google","googleapps","hubris","id","iport","iweb","k1","k10","k11","k12","k13","k14","k15","k16","k17","k18","k19","k2","k20","k3","k4","k5","k6","k7","k8","k9","key","key1","key10","key11","key12","key13","key14","key15","key16","key17","key18","key19","key2","key20","key3","key4","key5","key6","key7","key8","key9","lists","ls1","ls10","ls11","ls12","ls13","ls14","ls15","ls16","ls17","ls18","ls19","ls2","ls20","ls3","ls4","ls5","ls6","ls7","ls8","ls9","m","m1","m10","m1024","m11","m12","m13","m14","m15","m16","m17","m18","m19","m2","m20","m2048","m3","m384","m4","m5","m512","m6","m7","m768","m8","m9","mail","mailchannels","mailchannels1","mailchannels2","mailchannels3","mailchannels4","mailchannels5","mail-dkim","mail-in","mailjet","mailo","mailrelay","main","mandrill","mcdkim","mcdkim1","mcdkim2","mcdkim3","mcdkim4","mcdkim5","mdaemon","mesmtp","mikd","mimecast","mimecast20230622","mimi","mkt","monkey","msa","mx","mxvault","my1","my10","my11","my12","my13","my14","my15","my16","my17","my18","my19","my2","my20","my3","my4","my5","my6","my7","my8","my9","neomailout","one","originating","outbound","pf2005","pf2006","pf2007","pf2008","pf2009","pf2010","pf2011","pf2012","pf2013","pf2014","pf2015","pf2016","pf2017","pf2018","pf2019","pf2020","pf2021","pf2022","pf2023","pf2024","pm","pmta","postfix","postfix.private","postmark","pp","pp1","pp2","pp3","pp4","pp5","pp6","pp7","pp8","pp9","primary","primus","private","prod","proddkim","proddkim1024","proddkim2048","proddkim256","proddkim384","proddkim512","proddkim768","protonmail","protonmail1","protonmail2","protonmail3","protonmail4","publickey","pub","pvt","qcdkim","responsys","rit1608","rsa1","rsa10","rsa11","rsa12","rsa13","rsa14","rsa15","rsa16","rsa17","rsa18","rsa19","rsa2","rsa20","rsa3","rsa4","rsa5","rsa6","rsa7","rsa8","rsa9","s","s1","s10","s1024","s11","s12","s13","s14","s15","s16","s17","s18","s19","s2","s20","s2005","s2006","s2007","s2008","s2009","s2010","s2011","s2012","s2013","s2014","s2015","s2016","s2017","s2018","s2019","s2020","s2021","s2022","s2023","s2024","s2048","s2048g1","s3","s384","s4","s5","s512","s6","s7","s768","s8","s9","safe","sailthru","sasl","scarlet","scooby","scph0121","scph0919","sel1","sel10","sel11","sel12","sel13","sel14","sel15","sel16","sel17","sel18","sel19","sel2","sel20","sel3","sel4","sel5","sel6","sel7","sel8","sel9","selector","selector1","selector10","selector11","selector12","selector13","selector14","selector15","selector16","selector17","selector18","selector19","selector2","selector20","selector3","selector4","selector5","selector6","selector7","selector8","selector9","server","ses","sfmc48","sharedpool","sitemail","sl","sl1","sl10","sl11","sl12","sl13","sl14","sl15","sl16","sl17","sl18","sl19","sl2","sl20","sl3","sl4","sl5","sl6","sl7","sl8","sl9","sm","sm1024","smtp","smtpapi","smtpauth","smtpcomcustomers","smtpout","snowcrash","socketlabs","sparkpost","spf","spop","spop1024","squaremail","stigmate","test","testdk","testdkim","testdkim1024","testdkim2048","testdkim256","testdkim384","testdkim512","testdkim768","tilprivate","turbosmtp","v1","v2","v3","v4","v5","vzrelay","wesmail","www","x","yandex","yesmail1","yesmail10","yesmail11","yesmail12","yesmail13","yesmail14","yesmail15","yesmail16","yesmail17","yesmail18","yesmail19","yesmail2","yesmail20","yesmail3","yesmail4","yesmail5","yesmail6","yesmail7","yesmail8","yesmail9","yibm","yousendit","zendesk1","zoho"];
const stringsArray = ["arc","arc-384","arc-512","arc-768","arc-1024","arc-2048","arc-4096","arc-seal","arc-2000","arc-2001","arc-2002","arc-2003","arc-2004","arc-2005","arc-2006","arc-2007","arc-2008","arc-2009","arc-2010","arc-2011","arc-2012","arc-2013","arc-2014","arc-2015","arc-2016","arc-2017","arc-2018","arc-2019","arc-2020","arc-2021","arc-2022","arc-2023","arc-2024","arc-2025","zohoarc","arcs","arcsel","arcselector","arcselector9901","arc-20160816"];

  
// Global variable to check if the root domain's dmarc policy is set to reject. This is important for subdomains
let DMARCSubDomainSpoofable = true;
let SPFSubDomainSpoofable = true;

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

    function notify(title, message) {
        browser.notifications.create("domain-notification", {
            "type": "basic",
            "iconUrl": browser.runtime.getURL("icons/mailfail-128x128.png"),
            "title": title,
            "message": message
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
                                if (!isSubDomain){
                                    if (eachRecord.includes("+all")){
                                        SPFSubDomainSpoofable = true;
                                    } else if (eachRecord.includes("?all")){
                                        SPFSubDomainSpoofable = true;
                                    } else {
                                        SPFSubDomainSpoofable = false;
                                    }
                                }
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
                                            notify("Serious SPF Misconfiguration Found","The SPF record included reference to an authoritative domain that you can purchase and spoof valid emails from");
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
                                    const mx = eachRecord.split(' ')[1].replace(/\.$/, ''); // remove MX priority abnd trailing dot
                                    addItemToDNSRecordList(mx + `<img src="https://icons.duckduckgo.com/ip3/${getRootDomain(mx)}.ico" style=width:23px;height:23px;max-width:100%;max-height:100%;float:right;>`, DNSRecordList);
                                } else {
                                    addItemToDNSRecordList(eachRecord + `<img src="https://icons.duckduckgo.com/ip3/${getRootDomain(eachRecord.replace(/\.$/, ''))}.ico" style=width:23px;height:23px;max-width:100%;max-height:100%;float:right;>`, DNSRecordList);
                                }
                            } else if (eachRecord.includes("mail.protection.outlook.com") || eachRecord.includes("mail.protection.partner.outlook.cn")) {
                                let SMTPServer = eachRecord.split(' ')[1];
                                // Removes the warning banner added to suspicious emails in Outlook
                                const hideWarningBanner = "&lt;style&gt;table,tr{width:1px;height:1px;display:none;}&lt;/style&gt;"
                                addItemToDNSRecordList(SMTPServer + `<img src="https://icons.duckduckgo.com/ip3/${getRootDomain(SMTPServer).replace(/\.$/, '')}.ico" style=width:23px;height:23px;max-width:100%;max-height:100%;float:right;>`, DNSRecordList);
                                addItemToDNSRecordList(`${RED}Send-MailMessage -SmtpServer ${SMTPServer} -To Victim@${domainName} -From informationsecurity@${domainName} -Subject “Test” -Body “${hideWarningBanner}Test” -BodyAsHTML -DeliveryNotificationOption Never -Priority High -UseSsl${END}`, DNSRecordList);
                                incrementBadgeForCurrentTab();
                            }
                        }
                        if (headerText === "BIMI") {
                            if (eachRecord.startsWith("v=BIMI1")){
                                const blue = ["l="];
                                const green = ["a="];
                                highlightSubstrings(DNSRecordList, [], blue, green, eachRecord);

                                var pattern = /l=([^;]+)/;
                                var match = pattern.exec(eachRecord);
                                if (match && match.length > 1) {
                                    var url = match[1];
                                    // Security Concern XSS
                                    BIMI_IMG = `<a href="${url}" class="centered"><img src=${url} style=width:50px;height:50px;max-width:100%;max-height:100%;></a>`;
                                    addItemToDNSRecordList(BIMI_IMG, DNSRecordList);
                                }
                            }
                        }
                        if (headerText === "MTA-STS"){
                            if (eachRecord.includes("v=STSv1")){
                                if (eachRecord.startsWith("v=STSv1")){
                                    addItemToDNSRecordList(eachRecord, DNSRecordList);
                                    MTASTS_File = fetchMtaSts(domainName).then(mtastsText => {
                                        if (mtastsText){
                                            let red = ["mode: testing", "sts: false", "all: false", "include_subdomains: false"];
                                            let blue = [];
                                            let green = ["mode: enforce", "sts: true", "all: true", "include_subdomains: true"];
                                            highlightSubstrings(DNSRecordList, red, blue, green, mtastsText);
                                        } else{
                                            addItemToDNSRecordList(`<a href="https://mta-sts.${domainName}/.well-known/mta-sts.txt" style="text-decoration: none;"><span style="color: blue;text-align: center;">Click Here to Get the MTA-STS Text File.</span></a>`, DNSRecordList);
                                        }
                                    });

                                } else{
                                    addItemToDNSRecordList(eachRecord, DNSRecordList);
                                    addItemToDNSRecordList(`<span style="color: red;">Invalid MTA-STS Record. It Must Start with "v=STSv1".</span>`, DNSRecordList);
                                    MTASTS_File = fetchMtaSts(domainName).then(mtastsText => {
                                        if (mtastsText){
                                            addItemToDNSRecordList(mtastsText, DNSRecordList);
                                        } else{
                                            addItemToDNSRecordList(`<a href="https://mta-sts.${domainName}/.well-known/mta-sts.txt" style="text-decoration: none;"><span style="color: blue;text-align: center;">Click Here to Get the MTA-STS Text File.</span></a>`, DNSRecordList);
                                        }
                                    });
                                }
                            }
                        }
                        
                    });
                }

                // These headers should always show up
                if (headerText === "SPF") {
                    createHeader(PopUpDiv, domainName, headerText, `https://dmarcian.com/spf-survey/?domain=${domainName}`);
                } else if (headerText === "DMARC") {
                    createHeader(PopUpDiv, domainName, headerText, `https://dmarcian.com/dmarc-inspector/?domain=${domainName}`);
                } else if (headerText === "MX") {
                    createHeader(PopUpDiv, domainName, headerText, `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${domainName}&run=toolpage`);
                } 

                // Only add these headers if the data was found
                if(DNSRecordList.innerText !== ""){
                    if (headerText === "MTA-STS"){
                        createHeader(PopUpDiv, domainName, headerText, `https://mta-sts.${domainName}/.well-known/mta-sts.txt`);
                    } else if (headerText === "BIMI"){
                        createHeader(PopUpDiv, domainName, headerText, `https://bimigroup.org/bimi-generator/`);
                    }
                }

                // if the subdomain is not spoofable and the subdomain record doesnt exist
                if (isSubDomain && !SPFSubDomainSpoofable && !SPFExists && headerText === "SPF") {
                    addItemToDNSRecordList(`No Subdomain SPF Record Found. The Root Domain SPF Policy is Applied.`, DNSRecordList);
                } else if (headerText === "SPF" && !SPFExists && SPFSubDomainSpoofable){
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`${RED}No SPF Record Found or the Root Domain was Misconfigured. Email Spoofing is Possible.${END}`, DNSRecordList);
                }

                // if the subdomain is not spoofable and the subdomain record doesnt exist
                if (isSubDomain && !DMARCSubDomainSpoofable && DMARCCount === 0 && headerText === "DMARC") {
                    addItemToDNSRecordList(`No Subdomain DMARC Record Found. The Root Domain DMARC Policy is Applied.`, DNSRecordList);
                } else if (DMARCCount === 0 && headerText === "DMARC") {
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`${RED}No DMARC Record Found or the Root Domain was Misconfigured. Email Spoofing is Possible.${END}`, DNSRecordList);
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

    function sanitizeSVG(svgString) {
        const parser = new DOMParser();
        const svgDoc = parser.parseFromString(svgString, "image/svg+xml");
        const scripts = svgDoc.querySelectorAll("script");
    
        scripts.forEach(script => {
            script.parentNode.removeChild(script);
        });
    
        return svgDoc.documentElement.outerHTML;
    }
    
    function validateAndSanitizeSVG(svgUrl, callback) {
        fetch(svgUrl)
            .then(response => response.text())
            .then(svgString => {
                const sanitizedSVG = sanitizeSVG(svgString);
                callback(sanitizedSVG);
            })
            .catch(error => {
                // Error fetching or parsing SVG
                console.error('Error:', error);
                callback(null);
            });
    }

    async function fetchMtaSts(domainName) {
        try {
          const url = `https://mta-sts.${domainName}/.well-known/mta-sts.txt`;
          const response = await fetch(url);
      
          if (!response.ok) {
            return null;
          }
      
          const text = await response.text();
          return text;
        } catch (error) {
          return null;
        }
      }
      

      async function getRSAKeySize(dkimRecord, selector) {
        if (selector === "m1"){
            let a = 0;
        }
        const pMatch = dkimRecord.match(/p=([^\s;]+)/);
        if (!pMatch) return 0; // Couldn't find the RSA key
    
        const key = pMatch[1];
        try {
            const keyBinaryString = atob(key); // Decode Base64 string
            const keyUint8Array = new Uint8Array(keyBinaryString.length);
            for (let i = 0; i < keyBinaryString.length; ++i) {
                keyUint8Array[i] = keyBinaryString.charCodeAt(i);
            }
            const keyImported = await crypto.subtle.importKey(
                "spki",
                keyUint8Array.buffer,
                { name: "RSA-PSS", hash: "SHA-256" },
                true,
                ["verify"]
            );
    
            return keyImported.algorithm.modulusLength;
        } catch (error) {
            console.error("Error importing RSA key:", error, selector);
            return null;
        }
    }
    
    

    async function getDKIMRecord(DKIMRecord) {
        const response = await fetch(DKIMRecord, {
            headers: {
                'Accept': 'application/dns-json'
            }
        });
        if (!response.ok) {
            return null;
        }

        const data = await response.json();
        const dkimRecords = data.Answer && data.Answer.filter(record => record.type === 16); // TXT records have type 16
        if (!dkimRecords || dkimRecords.length === 0) {
            return null;
        }

        // Assume first TXT record contains DKIM information
        return dkimRecords[0].data;
    }

    async function DKIM(domainName){
        const container = document.querySelector('.container');
        const PopUpDiv = document.createElement('div');
        const DNSRecordList = document.createElement('ul');
        let num_DKIM = 0;
        createHeader(PopUpDiv, domainName, "DKIM", `https://dmarcian.com/dkim-inspector/?domain=${domainName}`);
        const DKIMRecordPromises = DKIMSelectors.map(async (selector) => {
            const DKIMURL = `https://cloudflare-dns.com/dns-query?name=${selector}._domainkey.${domainName}&type=TXT`;
            let dkimRecord = await getDKIMRecord(DKIMURL);
            if (dkimRecord) {
                num_DKIM += 1;
                dkimRecord = dkimRecord.replace(/"/g, ''); // Remove all quotes
                const rsaKeySize = await getRSAKeySize(dkimRecord, selector); // can return null
                if (rsaKeySize && rsaKeySize < 1024){
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`RSA-Key Size: <span style="color: red;">${rsaKeySize}</span></br>` + `Selector: <span style="color: red;">${selector}</span></br><span style="color: red;">${selector}._domainkey.${domainName}</span></br></br>` + dkimRecord, DNSRecordList);
                    addItemToDNSRecordList(`<span style="color: red;">Cryptographically Insecure Selector "${selector}" Detected. DKIM Private Key Can be Recovered.</span>`, DNSRecordList);
                    notify("Cryptographically Broken RSA Key",`The ${selector} DKIM selector on ${domainName} uses a ${rsaKeySize}-bit RSA key.`);
                } else if (rsaKeySize && rsaKeySize >= 1024){
                    addItemToDNSRecordList(`RSA-Key Size: <span style="color: green;">${rsaKeySize}</span></br>` + `Selector: <span style="color: blue;">${selector}</span></br><span style="color: blue;">${selector}._domainkey.${domainName}</span></br></br>` + dkimRecord, DNSRecordList);
                } else if (!rsaKeySize){ // if null then key is corrupted
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`RSA-Key Size: <span style="color: red;">Corrupted Public Key!</span></br>` + `Selector: <span style="color: red;">${selector}</span></br><span style="color: red;">${selector}._domainkey.${domainName}</span></br></br>` + dkimRecord, DNSRecordList);
                }
                if (rsaKeySize && !dkimRecord.startsWith("v=DKIM1")){  //https://datatracker.ietf.org/doc/html/rfc6376/#section-3.6.1
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`<span style="color: red;">DKIM Record Does Not Conformed to RFC-6376 Specifications. It Must Start With v=DKIM1. It Could Also be an ARC Key.</span>`, DNSRecordList);
                }
            }
        });

        await Promise.all(DKIMRecordPromises);
        if (num_DKIM > 0){
            PopUpDiv.appendChild(DNSRecordList);
            container.appendChild(PopUpDiv);
        }else{
            addItemToDNSRecordList(`This Domain Does Not Likely Use DKIM.`, DNSRecordList);
            PopUpDiv.appendChild(DNSRecordList);
            container.appendChild(PopUpDiv);
        }

    }

    async function ARC(domainName){
        const container = document.querySelector('.container');
        const PopUpDiv = document.createElement('div');
        const DNSRecordList = document.createElement('ul');
        let num_ARC = 0;
        createHeader(PopUpDiv, domainName, "ARC", `https://proton.me/blog/what-is-authenticated-received-chain-arc`);
        const ARCRecordPromises = ARCSelectors.map(async (selector) => {
            const ARCURL = `https://cloudflare-dns.com/dns-query?name=${selector}._domainkey.${domainName}&type=TXT`;
            let ARCRecord = await getDKIMRecord(ARCURL);
            if (ARCRecord) {
                num_ARC += 1;
                ARCRecord = ARCRecord.replace(/"/g, ''); // Remove all quotes
                const rsaKeySize = await getRSAKeySize(ARCRecord, selector); // can return null
                if (rsaKeySize && rsaKeySize < 1024){
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`RSA-Key Size: <span style="color: red;">${rsaKeySize}</span></br>` + `Selector: <span style="color: red;">${selector}</span></br><span style="color: red;">${selector}._domainkey.${domainName}</span></br></br>` + ARCRecord, DNSRecordList);
                    addItemToDNSRecordList(`<span style="color: red;">Cryptographically Insecure Selector "${selector}" Detected. ARC Private Key Can be Recovered.</span>`, DNSRecordList);
                    notify("Cryptographically Broken RSA Key",`The ${selector} ARC selector on ${domainName} uses a ${rsaKeySize}-bit RSA key.`);
                } else if (rsaKeySize && rsaKeySize >= 1024){
                    addItemToDNSRecordList(`RSA-Key Size: <span style="color: green;">${rsaKeySize}</span></br>` + `Selector: <span style="color: blue;">${selector}</span></br><span style="color: blue;">${selector}._domainkey.${domainName}</span></br></br>` + ARCRecord, DNSRecordList);
                } else if (!rsaKeySize){ // if null then key is corrupted
                    incrementBadgeForCurrentTab();
                    addItemToDNSRecordList(`RSA-Key Size: <span style="color: red;">Corrupted Public Key!</span></br>` + `Selector: <span style="color: red;">${selector}</span></br><span style="color: red;">${selector}._domainkey.${domainName}</span></br></br>` + ARCRecord, DNSRecordList);
                }
                // No version tag in ARC https://datatracker.ietf.org/doc/html/rfc8617#section-4.1.2
            }
        });

        await Promise.all(ARCRecordPromises);
        if (num_ARC > 0){
            PopUpDiv.appendChild(DNSRecordList);
            container.appendChild(PopUpDiv);
        }else{
            addItemToDNSRecordList(`This Domain Does Not Likely Use ARC.`, DNSRecordList);
            PopUpDiv.appendChild(DNSRecordList);
            container.appendChild(PopUpDiv);
        }

    }

    function fetchMailCheckResults(subDomain, rootDomain) {
        // Check Root Domain
        if (subDomain !== rootDomain) {
            const apiUrlTXTRoot = `https://cloudflare-dns.com/dns-query?name=${rootDomain}&type=TXT`;
            const apiUrlMXRoot = `https://cloudflare-dns.com/dns-query?name=${rootDomain}&type=MX`;
            const apiUrlDMARCRoot = `https://cloudflare-dns.com/dns-query?name=_dmarc.${rootDomain}&type=TXT`;
            const apiUrlBIMIRoot = `https://cloudflare-dns.com/dns-query?name=default._bimi.${rootDomain}&type=TXT`;
            const apiUrlMTASTSRoot = `https://cloudflare-dns.com/dns-query?name=_mta-sts.${rootDomain}&type=TXT`;
            checkRecord(apiUrlMXRoot, rootDomain, 'MX');
            checkRecord(apiUrlTXTRoot, rootDomain, 'SPF');
            checkRecord(apiUrlDMARCRoot, rootDomain, 'DMARC');
            checkRecord(apiUrlBIMIRoot, rootDomain, 'BIMI');
            checkRecord(apiUrlMTASTSRoot, rootDomain, 'MTA-STS');
            DKIM(rootDomain);
            ARC(rootDomain);
        }
        // Check Subdomain
        const apiUrlTXT = `https://cloudflare-dns.com/dns-query?name=${subDomain}&type=TXT`;
        const apiUrlMX = `https://cloudflare-dns.com/dns-query?name=${subDomain}&type=MX`;
        const apiUrlDMARC = `https://cloudflare-dns.com/dns-query?name=_dmarc.${subDomain}&type=TXT`;
        const apiUrlBIMI = `https://cloudflare-dns.com/dns-query?name=default._bimi.${subDomain}&type=TXT`;
        const apiUrlMTASTS = `https://cloudflare-dns.com/dns-query?name=_mta-sts.${subDomain}&type=TXT`;
        checkRecord(apiUrlMX, subDomain, 'MX');
        checkRecord(apiUrlTXT, subDomain, 'SPF');
        checkRecord(apiUrlDMARC, subDomain, 'DMARC');
        checkRecord(apiUrlBIMI, subDomain, 'BIMI');
        checkRecord(apiUrlMTASTS, subDomain, 'MTA-STS');
        DKIM(subDomain);
        ARC(subDomain);
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
            const subDomain = encodeHtmlEntities(hostname);
            const rootDomain = encodeHtmlEntities(getRootDomain(hostname));
    
            // Update UI Links
            document.getElementById("hunterlink").href = `https://hunter.io/try/search/${rootDomain}?locale=en`; 
            document.getElementById("dnsquerieslink").href = `https://www.dnsqueries.com/en/smtp_test_check.php`; 
            document.getElementById("mxlink").href = `https://mxtoolbox.com/emailhealth/${rootDomain}/`; 
           
            fetchMailCheckResults(subDomain, rootDomain);
        } else{
            const container = document.querySelector('.container');
            const PopUpDiv = document.createElement('div');
            createHeader(PopUpDiv, hostname, "Domain is Not Valid", `#`);
            container.appendChild(PopUpDiv);
        }
    });
});
