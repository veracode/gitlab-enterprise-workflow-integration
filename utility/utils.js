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

/**
 * Normalizes severity strings from different scan types to a standard format
 * @param {string} severity - Severity string from scan results
 * @returns {string} Normalized severity string
 */
function normalizeSeverity(severity) {
    if (!severity) return '';
    
    // Normalize to string and trim whitespace
    const normalized = String(severity).trim();
    
    // Handle uppercase (IaC uses CRITICAL, HIGH, etc.)
    const upperSeverity = normalized.toUpperCase();
    
    // Map to standard severity names
    if (upperSeverity === 'CRITICAL' || normalized === 'Critical') {
        return 'Critical';
    } else if (upperSeverity === 'HIGH' || normalized === 'High' || normalized === ' High') {
        return 'High';
    } else if (upperSeverity === 'MEDIUM' || normalized === 'Medium') {
        return 'Medium';
    } else if (upperSeverity === 'LOW' || normalized === 'Low' || normalized === 'Low Risk') {
        return 'Low';
    } else if (upperSeverity === 'VERY_LOW' || normalized === 'Very Low') {
        return 'Very Low';
    } else if (upperSeverity === 'INFORMATIONAL' || normalized === 'Informational') {
        return 'Informational';
    }
    
    // Return original if no match
    return normalized;
}

/**
 * Gets the severity image URL from the project repository
 * Images are stored in the imgs folder in the same repository, always on 'main' branch
 * @param {string} severity - Severity string (will be normalized)
 * @param {string} projectUrl - Optional project URL (falls back to CI_PROJECT_URL)
 * @returns {string} Image URL or empty string if construction fails
 */
function getSeverityImageUrl(severity, projectUrl = null) {
    // Normalize severity first
    const normalizedSeverity = normalizeSeverity(severity);
    
    // Get project URL from environment variable (CI_PROJECT_URL) or fall back to passed parameter
    const currentProjectUrl = process.env.CI_PROJECT_URL || projectUrl;
    if (!currentProjectUrl) return '';
    
    // Map severity to image filename
    const imageMap = {
        'Critical': 'Very_High.png',
        'High': 'High.png',
        'Medium': 'Medium.png',
        'Low': 'Low.png',
        'Very Low': 'Very_Low.png',
        'Informational': 'Informational.png'
    };
    
    const imageFile = imageMap[normalizedSeverity];
    if (!imageFile) return '';
    
    // Construct GitLab raw file URL by appending the path to CI_PROJECT_URL
    // Format: {CI_PROJECT_URL}/-/raw/main/imgs/{filename}
    try {
        // Remove trailing slash from project URL if present
        const baseUrl = currentProjectUrl.replace(/\/$/, '');
        return `${baseUrl}/-/raw/main/imgs/${encodeURIComponent(imageFile)}`;
    } catch (error) {
        console.log('Error constructing image URL:', error.message);
        return '';
    }
}

/**
 * Creates a colored indicator using images for severity display
 * @param {string} severity - Severity string (will be normalized)
 * @param {string} projectUrl - Optional project URL (falls back to CI_PROJECT_URL)
 * @returns {string} Markdown image indicator or empty string if image URL can't be constructed
 */
function getColoredIndicator(severity, projectUrl = null) {
    const imageUrl = getSeverityImageUrl(severity, projectUrl);
    if (imageUrl) {
        const normalizedSeverity = normalizeSeverity(severity);
        return `![${normalizedSeverity}](${imageUrl})`;
    }
    // Fallback to empty string if image URL can't be constructed
    return '';
}

function initialScanInfo(scanType = 'Pipeline', scanResults = null, severityColors = null, projectUrl = null, branch = null){
    let scanMessage = '';
    
    switch(scanType) {
        case 'Pipeline':
            scanMessage = '![Veracode](https://analysiscenter.veracode.com/images/interface/veracodePlatformLogoSmall.png)<br> **Veracode Static Scan found flaws**';
            break;
        case 'Sandbox':
            scanMessage = '![Veracode](https://analysiscenter.veracode.com/images/interface/veracodePlatformLogoSmall.png)<br> **Veracode Static Scan found flaws**';
            break;
        case 'Policy':
            scanMessage = '![Veracode](https://analysiscenter.veracode.com/images/interface/veracodePlatformLogoSmall.png)<br> **Veracode Static Scan found flaws**';
            break;
        case 'SCA':
            scanMessage = '![Veracode](https://analysiscenter.veracode.com/images/interface/veracodePlatformLogoSmall.png)<br> **Veracode SCA Scan found vulnerabilities**';
            break;
        case 'IaC':
            scanMessage = '![Veracode](https://analysiscenter.veracode.com/images/interface/veracodePlatformLogoSmall.png)<br> **Veracode IaC/Secrets Scan found vulnerabilities/misconfigurations/secrets**';
            break;
        default:
            scanMessage = '![Veracode](https://analysiscenter.veracode.com/images/interface/veracodePlatformLogoSmall.png)<br> **Veracode Scan found issues**';
    }
    
    let output = scanMessage + '\n\n';
    
    // Add severity breakdown table for Pipeline scans
    if (scanType === 'Pipeline' && scanResults && Array.isArray(scanResults) && scanResults.length > 0) {
        // Count findings by severity
        const severityCounts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Very Low': 0,
            'Informational': 0
        };
        
        scanResults.forEach(result => {
            const severityText = severityType(result.severity);
            if (severityCounts.hasOwnProperty(severityText)) {
                severityCounts[severityText]++;
            }
        });
        
        // Create severity breakdown table
        output += '### Findings by Severity\n\n';
        output += '| Severity | Count |\n';
        output += '|----------|-------|\n';
        output += `| ${getColoredIndicator('Critical', projectUrl)} | ${severityCounts['Critical']} |\n`;
        output += `| ${getColoredIndicator('High', projectUrl)} | ${severityCounts['High']} |\n`;
        output += `| ${getColoredIndicator('Medium', projectUrl)} | ${severityCounts['Medium']} |\n`;
        output += `| ${getColoredIndicator('Low', projectUrl)} | ${severityCounts['Low']} |\n`;
        output += `| ${getColoredIndicator('Very Low', projectUrl)} | ${severityCounts['Very Low']} |\n`;
        output += `| ${getColoredIndicator('Informational', projectUrl)} | ${severityCounts['Informational']} |\n`;
        output += `| **Total** | **${scanResults.length}** |\n\n`;
    }
    
    // Add severity breakdown table for SCA scans
    if (scanType === 'SCA' && scanResults && scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities)) {
        // Count findings by severity (each vulnerability-library combination counts as one)
        const severityCounts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Very Low': 0,
            'Informational': 0
        };
        
        let totalCount = 0;
        scanResults.vulnerabilities.forEach(vulnerability => {
            const severityText = scaSeverityType(vulnerability.cvss3Score);
            // Count each library affected by this vulnerability
            const libraryCount = vulnerability.libraries ? vulnerability.libraries.length : 1;
            totalCount += libraryCount;
            
            // Normalize severity text (handle "Low Risk" and " High" with space)
            const normalizedSeverity = normalizeSeverity(severityText);
            if (severityCounts.hasOwnProperty(normalizedSeverity)) {
                severityCounts[normalizedSeverity] += libraryCount;
            }
        });
        
        // Create severity breakdown table
        output += '### Findings by Severity\n\n';
        output += '| Severity | Count |\n';
        output += '|----------|-------|\n';
        output += `| ${getColoredIndicator('Critical', projectUrl)} | ${severityCounts['Critical']} |\n`;
        output += `| ${getColoredIndicator('High', projectUrl)} | ${severityCounts['High']} |\n`;
        output += `| ${getColoredIndicator('Medium', projectUrl)} | ${severityCounts['Medium']} |\n`;
        output += `| ${getColoredIndicator('Low', projectUrl)} | ${severityCounts['Low']} |\n`;
        output += `| ${getColoredIndicator('Very Low', projectUrl)} | ${severityCounts['Very Low']} |\n`;
        output += `| ${getColoredIndicator('Informational', projectUrl)} | ${severityCounts['Informational']} |\n`;
        output += `| **Total** | **${totalCount}** |\n\n`;
    }
    
    // Add severity breakdown table for IaC scans
    if (scanType === 'IaC' && scanResults) {
        // Initialize counts for all severities across all three types
        const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Very Low', 'Informational'];
        const counts = {
            'Critical': { vulnerabilities: 0, misconfigurations: 0, secrets: 0 },
            'High': { vulnerabilities: 0, misconfigurations: 0, secrets: 0 },
            'Medium': { vulnerabilities: 0, misconfigurations: 0, secrets: 0 },
            'Low': { vulnerabilities: 0, misconfigurations: 0, secrets: 0 },
            'Very Low': { vulnerabilities: 0, misconfigurations: 0, secrets: 0 },
            'Informational': { vulnerabilities: 0, misconfigurations: 0, secrets: 0 }
        };
        
        // Count vulnerabilities by severity
        const vulnerabilityData = scanResults?.vulnerabilities?.matches || [];
        vulnerabilityData.forEach(result => {
            const severity = normalizeSeverity(result.vulnerability.severity);
            if (counts.hasOwnProperty(severity)) {
                counts[severity].vulnerabilities++;
            }
        });
        
        // Count misconfigurations by severity
        const misconfigurations = scanResults?.configs || [];
        misconfigurations.forEach(result => {
            const severity = normalizeSeverity(result.Severity);
            if (counts.hasOwnProperty(severity)) {
                counts[severity].misconfigurations++;
            }
        });
        
        // Count secrets by severity
        const secrets = scanResults?.secrets || [];
        secrets.forEach(result => {
            const severity = normalizeSeverity(result.Severity);
            if (counts.hasOwnProperty(severity)) {
                counts[severity].secrets++;
            }
        });
        
        // Create severity breakdown table
        output += '### Findings by Severity\n\n';
        output += '| Severity | Vulnerability | Misconfiguration | Secrets |\n';
        output += '|----------|---------------|------------------|--------|\n';
        severityOrder.forEach(severity => {
            output += `| ${getColoredIndicator(severity, projectUrl)} | ${counts[severity].vulnerabilities} | ${counts[severity].misconfigurations} | ${counts[severity].secrets} |\n`;
        });
        output += '\n';
    }
    
    return output;
}

function scaResult(scanResult){
    const vulnerabilities = scanResult.vulnerabilities.sort((a,b)=>  b.cvss3Score - a.cvss3Score);
    const libraries = scanResult.libraries;
    const projectUrl = process.env.CI_PROJECT_URL || process.env.PROJECT_URL;
    let output = initialScanInfo('SCA', scanResult, null, projectUrl);
    output+= '<details>\n'+
    '<summary>Scan Details</summary>\n\n'+
    '| Vulnerability ID | Severity | Description | Library | Version |\n' +
    '| ---------------- | -------- | ----------- | ------- | ------- |\n';
    vulnerabilities.forEach((vulnerability) => {
        vulnerability.libraries.forEach((library)=>{
        const libId = library._links.ref.split('/')[4];
        const lib = libraries[libId];
        const severityText = scaSeverityType(vulnerability.cvss3Score);
        const severityDisplay = `${getColoredIndicator(severityText, projectUrl)}`;
    output +=
        `| ${vulnerability.cve !== null ? `CVE-${vulnerability.cve}` : `NO-CVE`} `+
        `| ${severityDisplay} ` +
        `| ${vulnerability.title} ` +
        `| ${lib.name} ` +
        `| ${lib.versions[0].version} |\n`;
        });
    });
    output += '</details>\n'
    return output;
}

const { getSourceFilePath: getSourceFilePathService } = require('./service');

async function getSourceFilePath(filePath, branch, projectUrl, lineNumber) {
    return await getSourceFilePathService(filePath, branch, projectUrl, lineNumber);
}
async function pipelineResult(scanResult, branch, projectUrl){
    let output = initialScanInfo('Pipeline', scanResult, null, projectUrl, branch);
    
    output+= '<details>\n'+
    '<summary>Scan Details</summary>\n\n'+
    '<table>'+
    '<thead>'+
    '<tr>'+
      '<th> CWE ID </th>'+
      '<th> Severity </th>'+
      '<th> Source File </th>'+
      '<th> Issue Type / Details </th>'+
    '</tr>'+
    '</thead>'+
    '<tbody>';

    for (const result of scanResult) {
        const filePath = result.files.source_file.file;
        const lineNumber = result.files.source_file.line;
        const sourceFileLink = await getSourceFilePath(filePath, branch, projectUrl, lineNumber);
        const displayLink = sourceFileLink || `${filePath}:${lineNumber}`;
        const severityText = severityType(result.severity);
        const severityDisplay = `${getColoredIndicator(severityText, projectUrl)}`;
        
        output +=
        `<tr>
        <td> ${result.cwe_id} </td>
        <td> ${severityDisplay} </td>
        <td> [${filePath}:${lineNumber}](${displayLink}) </td>
        <td> ${result.issue_type} </td>
        </tr>
        <tr>
        <td colspan="4">
        <details><summary>Flaw Details</summary> ${result.display_text} </details>
        </td>
        </tr>`;
    }
    output += '</tbody></table></details>\n';
    return output;
}

function policyResult(scanResult){
    const projectUrl = process.env.CI_PROJECT_URL || process.env.PROJECT_URL;
    let output = initialScanInfo('Policy', null, null, projectUrl);
    output+= '<details>\n'+
    '<summary>Scan Details</summary>\n\n'+
    '| CWE ID | Severity | Issue Type | Category | Source File |\n' +
    '| ------ | -------- | ---------- | -------- | ----------- |\n';
    scanResult.forEach((result) => {
        const severityText = severityType(result.static.severity);
        const severityDisplay = `${getColoredIndicator(severityText, projectUrl)} ${severityText}`;
    output +=
        `| ${result.static.cwe_id} `+
        `| ${severityDisplay} ` +
        `| ${result.static.issue_type} ` +
        `| ${result.static.category} ` +
        `| Line ${result.static.line}: ${result.static.source_file} |\n`;
    });
    output += '</details>\n'
    return output;
}

 
function iacResult(scanResult){
    const projectUrl = process.env.CI_PROJECT_URL || process.env.PROJECT_URL;
    let output = initialScanInfo('IaC', scanResult, null, projectUrl);
    
    let IaCVulnerabilities = extractIaCVulnerabilities(scanResult, projectUrl);
    let IaCMisconfigurations = extractIaCMisconfigurations(scanResult, projectUrl);
    let IaCSecrets = extractIaCSecrets(scanResult, projectUrl);
    
    output += IaCVulnerabilities;
    output += IaCMisconfigurations;
    output += IaCSecrets;

    return output;
}

function extractIaCVulnerabilities(scanResult, projectUrl = null){
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
            MESSAGE       : result.vulnerability.description
        }));
    
        formattedVulnerabilities.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);
    
        output+= '<details>\n'+
        '<summary>Vulnerability Scan Details</summary>\n\n'+
        '| Severity  | Name     | Vulnerability | Installed  | Fixed-In      | Type        | Message        |\n' +
        '| --------  | -------- | ------------- | ---------  | --------------| ----------- | -------------- |\n';
        formattedVulnerabilities.forEach((result) => {
            const severityDisplay = `${getColoredIndicator(result.SEVERITY, projectUrl)}`;
        output += `| ${severityDisplay} | ${result.NAME} | ${result.VULNERABILITY} | ${result.INSTALLED} | ${result["FIXED_IN"]} | ${result.TYPE} | ${result.MESSAGE} |\n`;
        });
        output += '\n</details>\n';
    
        return output;        
}

function extractIaCMisconfigurations(scanResults, projectUrl = null) {
        let output = "";  
        const Misconfigurations = scanResults?.configs;
      
        if (Misconfigurations.length === 0) {
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
            MESSAGE     : result.Message === "No issues found" ? "-" : result.Message
        }));
        formattedData.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);

        output += '\n<details>\n' +
            '<summary>Misconfiguration Details</summary>\n\n' +
            '| SEVERITY | TITLE    |  ID   | PROVIDER | MESSAGE        |\n' +
            '| ------- | -------- | ----- | --------- | -------------- |\n';
        formattedData.forEach((result) => {
            const severityDisplay = `${getColoredIndicator(result.SEVERITY, projectUrl)}`;
            output +=
                `| ${severityDisplay} ` +
                `| ${result.TITLE} ` +
                `| ${result.ID} ` +
                `| Line ${result.PROVIDER} `+ 
                `| ${result.MESSAGE} |\n`
        });   
        output += '\n</details>\n';

        return output;
}

function extractIaCSecrets(scanResult, projectUrl = null){
        let output = "";
        const IacSecreteData = scanResult?.secrets || [];
        
        if(IacSecreteData.length == 0){
            output += "\n<details>\n";
            output += "<summary>Secrets Scan Details</summary>\n";
            output += "No Secrets found.\n";
            output += "</details>\n";
            return output;     
        }

        const formattedIacSecret = IacSecreteData.map((result) => ({
            SEVERITY      : result.Severity,
            SECRET_TYPE   : result.Title,
            FILE          : result.Target,
            MESSAGE       : result.Match
        }));
        formattedIacSecret.sort((a, b) => severityRank[b.SEVERITY] - severityRank[a.SEVERITY]);

        output+= '<details>\n'+
        '<summary>Secrets Scan Details</summary>\n\n'+
        '| Severity | SECRET_TYPE | FILE          | MESSAGE           |\n' +
        '| -------- | ----------- | ------------- | ----------------- |\n';
        formattedIacSecret.forEach((result) => {
            const severityDisplay = `${getColoredIndicator(result.SEVERITY, projectUrl)}`;
        output += `| ${severityDisplay} | ${result.SECRET_TYPE} | ${result.FILE} | ${result.MESSAGE} |\n`;
        });
        output += '\n</details>\n';

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