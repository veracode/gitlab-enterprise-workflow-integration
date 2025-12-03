var parseString = require('xml2js').parseString;
const fs = require('fs');
const path = require('path');
const {VERACODE_FLAW_LABELS} = require('../utility/labels');

function processStaticResultsXML(xml){
    const severityArray = ['Informational','Very Low','Low','Medium','High','Very High']

    let policy_results = {
        scan_types: ["Static Analysis"],
        num_findings: 0,
        num_very_high: 0,
        num_high: 0,
        num_medium: 0,
        num_low: 0,
        num_very_low: 0,
        num_informational: 0,
        findings: []
    }
    let all_results = {
        scan_types: ["Static Analysis"],
        num_findings: 0,
        num_very_high: 0,
        num_high: 0,
        num_medium: 0,
        num_low: 0,
        num_very_low: 0,
        num_informational: 0,
        findings: []
    }

    parseString(xml, function (_err, result) {
        // Convert XML to well defined Object
        let output = JSON.stringify(result, null, 2)
        output = output.replace("static-analysis", "static_analysis");
        output = output.replace("flaw-status", "flaw_status");
        output = output.replace("xmlns:xsi", "xmlns_xsi");
        output = output.replace("xsi:schemaLocation", "xsi_schemaLocation");
        output = output.replace("sev-1-change", "sev_1_change");
        output = output.replace("sev-2-change", "sev_2_change");
        output = output.replace("sev-3-change", "sev_3_change");
        output = output.replace("sev-4-change", "sev_4_change");
        output = output.replace("sev-5-change", "sev_5_change");
        const res = JSON.parse(output);
        // console.log('res in results file', res)
        // Iterate through the Sevrities
        for (let i=0; i<res.detailedreport.severity.length; i++) {
            let severity = parseInt(res.detailedreport.severity[i].$.level); 
            let theCategory = res.detailedreport.severity[i].category;
            if (theCategory) {
                for (let j=0; j< theCategory.length; j++) {
                    for (let k=0; k<theCategory[j].cwe.length; k++) {
                        for (let l=0; l<theCategory[j].cwe[k].staticflaws.length; l++) {
                            for (let m=0; m<theCategory[j].cwe[k].staticflaws[l].flaw.length; m++) {
                                let static_finding = {
                                    issue_id: parseInt(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.issueid),
                                    severity: parseInt(res.detailedreport.severity[i].$.level),
                                    severity_text: severityArray[parseInt(res.detailedreport.severity[i].$.level)],
                                    category: theCategory[j].$.categoryname,
                                    cwe_id: theCategory[j].cwe[k].$.cweid,
                                    issue_type: theCategory[j].cwe[k].$.cwename,
                                    source_file: theCategory[j].cwe[k].staticflaws[l].flaw[m].$.sourcefilepath+theCategory[j].cwe[k].staticflaws[l].flaw[m].$.sourcefile,
                                    line: parseInt(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.line),
                                    function_prototype: theCategory[j].cwe[k].staticflaws[l].flaw[m].$.functionprototype,
                                    description: extractDescriptionXML(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.description),
                                    remediation: extractRemediationXML(theCategory[j].cwe[k].staticflaws[l].flaw[m].$.description),
                                    additional_remediation: ""
                                }
                                let finding = {
                                    type: "Static Analysis",
                                    static: static_finding
                    
                                }
                                // Add to All Findings
                                all_results.findings.push(finding);
                                switch (static_finding.severity) {
                                    case 0: { 
                                        all_results.num_informational++;
                                        break; 
                                    } 
                                    case 1: { 
                                        all_results.num_very_low++;
                                        break; 
                                    } 
                                    case 2: { 
                                        all_results.num_low++;
                                        break; 
                                    } 
                                    case 3: { 
                                        all_results.num_medium++;
                                        break; 
                                    } 
                                    case 4: { 
                                        all_results.num_high++;
                                        break; 
                                    } 
                                    case 5: { 
                                        all_results.num_very_high++;
                                        break; 
                                    } 
                                }
                                all_results.num_findings++;
                                // Add to Policy Findings
                                if (theCategory[j].cwe[k].staticflaws[l].flaw[m].$.affects_policy_compliance === "true") {
                                    policy_results.findings.push(finding);
                                    switch (static_finding.severity) {
                                        case 0: { 
                                            policy_results.num_informational++;
                                            break; 
                                        } 
                                        case 1: { 
                                            policy_results.num_very_low++;
                                            break; 
                                        } 
                                        case 2: { 
                                            policy_results.num_low++;
                                            break; 
                                        } 
                                        case 3: { 
                                            policy_results.num_medium++;
                                            break; 
                                        } 
                                        case 4: { 
                                            policy_results.num_high++;
                                            break; 
                                        } 
                                        case 5: { 
                                            policy_results.num_very_high++;
                                            break; 
                                        } 
                                    }
                                    policy_results.num_findings++;
                                }
                            }
                        }
                    }

                }
            }
        }
    
        //fs.writeFileSync('./detailedreport.json', output);
    });

    let report = {
        policy_results: policy_results,
        all_results: all_results
    }

    return report;
}

function extractDescriptionXML(details)  {
    let parts = details.split("\r\n\r\n");
    if (parts.length < 2) {
      return details;
    } else {
      return parts[0].replace("\r\n\r\n", "\r\n")
    }
}

function extractRemediationXML(details){
    let parts = details.split("\r\n\r\n");
    if (parts.length == 1) {
      return details;
    } else if (parts.length == 2) {
      return parts[1].replace("\r\n\r\n", "\r\n")
    } else {
        return (parts[1] + " \r\n" + parts[2]).replace("\r\n\r\n", "\r\n");
    }
}

async function attacheResult(veracodeArtifactsDir, fileName, result) {
    try {
        const filePath = path.join(veracodeArtifactsDir, fileName);
        fs.writeFileSync(filePath, result);
    } catch (error) {
        console.error(`Error while writing ${fileName}`);
        console.log(error);
    }
}

function exitOnFailure(exitStatus) {
    if (exitStatus) {
        process.exit(1);
    }
}

async function uploadArtifact(veracodeArtifactsDir, artifactName, simplifiedFileName, result) {
    try {
       // Create folder path using the artifact name
        const folderPath = path.join(veracodeArtifactsDir, artifactName);
        // Create the folder if it doesn't exist
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath, { recursive: true });
        }
        attacheResult(folderPath, simplifiedFileName, result)
        console.log(`Attaching the results under ${folderPath}/${simplifiedFileName}`);
    } catch (error) {
        console.error(`Error while processing ${fileName}`);
        console.error(error);
    }
}

function updateErrorMessage(breakBuildOnError, userErrorMessage, error) {
    return breakBuildOnError ? userErrorMessage : error;
}

function getScaIssueDetails(vulnerability,library){ 
    const vulnerabilityLibraryDetails = vulnerability.libraries[0].details[0];
    const severityLabel = getSeverityName('sca',vulnerability.cvssScore);
    const CVE = vulnerability.cve || '0000-0000';
    const version = library.versions.map(version => version.version);
    var title = `CVE: ${CVE} found in ${library.name} - ${vulnerability.title} - Version: ${version} [${vulnerability.language}]`;
    var labels = `Veracode SCA Scan,${severityLabel}`;
    var description = "Veracode Software Composition Analysis"+
        "  \n===============================\n"+
        "  \n Attribute | Details"+
        "  \n| --- | --- |"+
        "  \nLibrary | "+library.name+
        "  \nDescription | "+library.description+
        "  \nLanguage | "+vulnerability.language+
        "  \nVulnerability | "+vulnerability.title+
        "  \nVulnerability description | "+(vulnerability.overview ? vulnerability.overview.trim() : "")+
        "  \nCVE | "+vulnerability.cve+
        "  \nCVSS score | "+vulnerability.cvssScore+
        "  \nVulnerability present in version/s | "+vulnerabilityLibraryDetails.versionRange+
        "  \nFound library version/s | "+version+
        "  \nVulnerability fixed in version | "+vulnerabilityLibraryDetails.updateToVersion+
        "  \nLibrary latest version | "+library.latestRelease+
        "  \nFix | "+vulnerabilityLibraryDetails.fixText+
        "  \n"+
        "  \nLinks:"+
        "  \n- "+library.versions[0]._links.html+
        "  \n- "+vulnerability._links.html+
        "  \n- Patch: "+vulnerabilityLibraryDetails.patch;

    return {
        title,description,labels
    };
}

function getSeverityName(scanType,cvss){
    var weight = Math.floor(cvss);
    let label = VERACODE_FLAW_LABELS.Unknown.name;
    if (weight == 0)
        label = VERACODE_FLAW_LABELS.Informational.name;
    else if ((scanType == 'sca' && weight >= 0.1 && weight < 1.9) || (scanType == 'static' && weight == 1))
        label = VERACODE_FLAW_LABELS['Very Low'].name;
    else if ((scanType == 'sca' && weight >= 2.0 && weight < 3.9) || (scanType == 'static' && weight == 2))
        label = VERACODE_FLAW_LABELS.Low.name;
    else if ((scanType == 'sca' && weight >= 4.0 && weight < 5.9) || (scanType == 'static' && weight == 3))
        label = VERACODE_FLAW_LABELS.Medium.name;
    else if ((scanType == 'sca' && weight >= 6.0 && weight < 7.9) || (scanType == 'static' && weight == 4))
        label = VERACODE_FLAW_LABELS.High.name;
    else if ((scanType == 'sca' && weight >= 8.0) || (scanType == 'static' && weight == 5))
        label = VERACODE_FLAW_LABELS['Very High'].name;

    return label;
}


function parseVeracodeFlawID(vid) {
    let parts = vid.split(':');
    if(parts.length == 4){
        return ({
            "prefix": parts[0],
            "cwe": parts[1],
            "file": parts[2],
            "line": parts[3].substring(0, parts[3].length - 1)
        })
    }else{
        return ({
            "prefix": parts[0],
            "flawNum": parts[1].substring(0, parts[1].length - 1),
        })
    }
}

function getVeracodeFlawID(title) {
    let start = title.indexOf('[VID');
    if(start == -1) {
        return null;
    }
    let end = title.indexOf(']', start);

    return title.substring(start, end+1);
}

function scaSeverityType(score){
    if (score == 0.0)
        return 'Informational'
    else if (score >= 0.1 && score <= 0.9)
        return 'Very Low'
     else if (score >= 1.0 && score <= 3.9)
       return 'Low Risk'
    else if (score >= 4.0 && score <= 6.9)
        return 'Medium'
    else if (score >= 7.0 && score <= 8.9)
       return ' High'
    else if (score >= 9.0 && score <= 10.0)
        return 'Critical'
}

function severityType(score){
    if (score == 0)
        return 'Informational'
    else if (score == 1)
        return 'Very Low'
     else if (score == 2)
       return 'Low'
    else if (score == 3)
        return 'Medium'
    else if (score == 4)
       return 'High'
    else if (score == 5)
        return 'Critical'
}

const severityRank = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "VERY_LOW": 1,
    "INFORMATIONAL":0
  };  

function initialScanInfo(){
    return '- :red_circle: **Critical**: Immediate attention required.\n' +
    '- :orange_circle: **High**: Serious but slightly lower priority than Critical.\n' +
    '- :yellow_circle: **Medium**: Moderate risk, to be fixed in a reasonable timeframe.\n' +
    '- :green_circle: **Low**: Minimal risk, can be addressed in the normal course of development.\n' +
    '- :blue_circle: **Very Low**: Recommendations or low-priority findings.\n' +
    '- :white_circle: **Informational**: No security impact, can be ignored.\n'
}

function scaResult(scanResult){
    const vulnerabilities = scanResult.vulnerabilities.sort((a,b)=>  b.cvss3Score - a.cvss3Score);
    const libraries = scanResult.libraries;
    let output = initialScanInfo();
    output+= '<details>\n'+
    '<summary>Scan Details</summary>\n\n'+
    '| Vulnerability ID | Severity | Description | Library | Version |\n' +
    '| ---------------- | -------- | ----------- | ------- | ------- |\n';
    vulnerabilities.forEach((vulnerability) => {
        vulnerability.libraries.forEach((library)=>{
        const libId = library._links.ref.split('/')[4];
        const lib = libraries[libId];
    output +=
        `| ${vulnerability.cve !== null ? `CVE-${vulnerability.cve}` : `NO-CVE`} `+
        `| ${scaSeverityType(vulnerability.cvss3Score)} ` +
        `| ${vulnerability.title} ` +
        `| ${lib.name} ` +
        `| ${lib.versions[0].version} |\n`;
        });
    });
    output += '</details>\n'
    return output;
}

function pipelineResult(scanResult){
    let output = initialScanInfo();
    output+= '<details>\n'+
    '<summary>Scan Details</summary>\n\n'+
    '| CWE ID | Severity | Issue Type | Source File |\n' +
    '| ------ | -------- | ---------- | ----------- |\n';
    scanResult.forEach((result) => {
    output +=
        `| ${result.cwe_id} `+
        `| ${severityType(result.severity)} ` +
        `| ${result.issue_type} ` +
        `| Line ${result.files.source_file.line}: ${result.files.source_file.file} |\n`;
    });
    output += '</details>\n'
    return output;
}

function policyResult(scanResult){
    let output = initialScanInfo();
    output+= '<details>\n'+
    '<summary>Scan Details</summary>\n\n'+
    '| CWE ID | Severity | Issue Type | Category | Source File |\n' +
    '| ------ | -------- | ---------- | -------- | ----------- |\n';
    scanResult.forEach((result) => {
    output +=
        `| ${result.static.cwe_id} `+
        `| ${severityType(result.static.severity)} ` +
        `| ${result.static.issue_type} ` +
        `| ${result.static.category} ` +
        `| Line ${result.static.line}: ${result.static.source_file} |\n`;
    });
    output += '</details>\n'
    return output;
}

 
function iacResult(scanResult){
    
    let output = initialScanInfo();
    
    let IaCVulnerabilities = extractIaCVulnerabilities(scanResult);
    let IaCMisconfigurations = extractIaCMisconfigurations(scanResult);
    let IaCSecrets = extractIaCSecrets(scanResult);
    let IaCPolicyResults = extractIaCPolicyResults(scanResult);
    
    output += IaCVulnerabilities;
    output += IaCMisconfigurations;
    output += IaCSecrets;
    output += IaCPolicyResults;

    return output;
}

function extractIaCVulnerabilities(scanResult){
        let output = "";
        const vulnerabilityData = scanResult?.vulnerabilities?.matches || [];
        
        if(!vulnerabilityData || vulnerabilityData.length === 0){
            output += "<details>\n";
            output += "<summary>Vulnerability Scan Details</summary>\n\n";
            output += "No Vulnerabilities found.\n";
            output += "</details>\n";
            return output;         
        }

        const formattedVulnerabilities = vulnerabilityData.map((result) => ({
            SEVERITY      : result.vulnerability.severity,
            NAME          : result.artifact.name,
            VULNERABILITY : result.vulnerability.id,
            INSTALLED     : result.artifact.version,
            FIXED_IN      : result.vulnerability.fix.versions[0] || "N/A",
            TYPE          : result.artifact.type,
        }));
    
        formattedVulnerabilities.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);
    
        output+= '<details>\n'+
        '<summary>Vulnerability Scan Details</summary>\n\n'+
        '| Severity  | Name     | Vulnerability | Installed  | Fixed-In      | Type       |\n' +
        '| --------  | -------- | ------------- | ---------  | --------------| ----------- |\n';
        formattedVulnerabilities.forEach((result) => {
        output += `| ${result.SEVERITY} | ${result.NAME} | ${result.VULNERABILITY} | ${result.INSTALLED} | ${result["FIXED_IN"]} | ${result.TYPE} |\n`;
        });
        output += '\n</details>\n';
    
        return output;        
}

function extractIaCMisconfigurations(scanResults) {
        let output = "";  
        const Misconfigurations = scanResults?.configs?.Results?.[0]?.Misconfigurations;
      
        if (!Misconfigurations ||  Misconfigurations.length === 0) {
            output += "\n<details>\n";
            output += "<summary>Misconfiguration Details</summary>\n\n";
            output += "No Misconfigurations found.\n";
            output += "</details>\n";
            return output;
        }

        const formattedData = Misconfigurations.map((result) => ({
            SEVERITY    : result.Severity,
            TITLE       : result.Title,
            ID          : result.ID,
            PROVIDER    : result.CauseMetadata.Provider,
        }));
        formattedData.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);

        output += '\n<details>\n' +
            '<summary>Misconfiguration Details</summary>\n\n' +
            '| SEVERITY | TITLE    |  ID   | PROVIDER |\n' +
            '| ------- | -------- | ----- | ---------|\n';
        formattedData.forEach((result) => {
            output +=
                `| ${result.SEVERITY} ` +
                `| ${result.TITLE} ` +
                `| ${result.ID} ` +
                `| Line ${result.PROVIDER} |\n`;
        });   
        output += '\n</details>\n';

        return output;
}

function extractIaCSecrets(scanResult){
        let output = "";
        const IacSecreteData = scanResult?.secrets?.Results || [];
        
        if(!IacSecreteData || IacSecreteData.length == 0 ){
            output += "\n<details>\n";
            output += "<summary>Secrets Scan Details</summary>\n";
            output += "No Secrets found.\n";
            output += "</details>\n";
            return output;     
        }

        const formattedIacSecret = IacSecreteData.map((result) => ({
            SEVERITY      : result.Secrets[0].Severity,
            SECRET_TYPE   : result.Secrets[0].Title,
            FILE          : result.Target
        }));
        formattedIacSecret.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);

        output+= '<details>\n'+
        '<summary>Secrets Scan Details</summary>\n\n'+
        '| Severity | SECRET_TYPE | FILE |\n' +
        '| -------- | ----------- | -------------|\n';
        formattedIacSecret.forEach((result) => {
        output += `| ${result.SEVERITY} | ${result.SECRET_TYPE} | ${result.FILE} |\n`;
        });
        output += '\n</details>\n';

        return output;
}

function extractIaCPolicyResults(scanResult){
    let output = "";
    const IacPolicyResult = scanResult?.["policy-results"][0]?.failures || [];
    
    if(!IacPolicyResult|| IacPolicyResult.length == 0 ){
        output += "<details>\n";
        output += "<summary>Policy Evaluation Details</summary>\n";
        output += "No Policy found.\n";
        output += "</details>\n";
        return output;    
    }

    const formattedIacPolicyResult = IacPolicyResult.map((result) => {
        const severityMatch = result.msg.match(/Found (Critical|High|Medium|Low|Very_low|Informational)/);
        const ghsaMatch = result.msg.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/);
        return {
            SEVERITY        : severityMatch ? severityMatch[1] : "Unknown",
            VULNERABILITY   : ghsaMatch ? ghsaMatch[0] : "Unknown",
            MESSAGE         : result.msg  // Or extract this from the message if it varies
        };
    });
    formattedIacPolicyResult.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);

    output+= '<details>\n'+
    '<summary>Policy Evaluation Details</summary>\n\n'+
    '| SEVERITY | VULNERABILITY | MESSAGE |\n' +
    '| -------- | ----------- | -------------|\n';
    formattedIacPolicyResult.forEach((result) => {
    output += `| ${result.SEVERITY} | ${result.VULNERABILITY} | ${result.MESSAGE} |\n`;
    });
    output += '\n</details>';

    return output;
} 

module.exports = {
    processStaticResultsXML,
    attacheResult,
    exitOnFailure,
    uploadArtifact,
    updateErrorMessage,
    getScaIssueDetails,
    parseVeracodeFlawID,
    getSeverityName,
    getVeracodeFlawID,
    scaResult,
    pipelineResult,
    policyResult,
    iacResult
}