const { VERACODE_STATIC_LABELS, VERACODE_FLAW_LABELS } = require('../utility/labels');
const { listExistingOpenIssues, checkLabelExists, createLabels, createIssue } = require('../utility/service');
const { parseVeracodeFlawID, getSeverityName, getVeracodeFlawID } = require('../utility/utils');
async function pipelineScanIssue(flawData) {
    try{
        let flawFiles = new Map();
        const isLabelExist = await checkLabelExists(VERACODE_STATIC_LABELS[1].name);
        if(!isLabelExist){
            await createLabels([...Object.values(VERACODE_FLAW_LABELS), ...VERACODE_STATIC_LABELS]);
        }else{
            console.log("Labels already exist");
        }
        const existingOpenIssues = await listExistingOpenIssues("Veracode Pipeline Scan");
        existingOpenIssues.forEach(issue => {
            let flawID = getVeracodeFlawID(issue.title);
            // Map using VeracodeFlawID as index, for easy searching.  Line # for simple flaw matching
            if(flawID === null){
                console.log(`Flaw \"${issue.title}\" has no Veracode Flaw ID, ignored.`)
            } else {
                let flawInfo = parseVeracodeFlawID(flawID);
                let flaw = {'cwe': flawInfo.cwe,
                            'line': flawInfo.line};
                
                if(flawFiles.has(flawInfo.file)) {
                    // already have some flaws in this file, so just add this specific flaw to the array
                    let flaws = flawFiles.get(flawInfo.file);
                    flaws.push(flaw);
                } else {
                    // add this file into the map, with the fist of (possible) multiple flaws
                    flawFiles.set(flawInfo.file, [flaw])
                }
            }
        });
        let isIssueExists;
        for(const flaw of flawData.findings) {
            let vid = `[VID:${flaw.cwe_id}:${flaw.files.source_file.file}:${flaw.files.source_file.line}]`;
            if(flawFiles.has(flaw.files.source_file.file)) {
                // check all the flaws in this file to see if we have a match
                for(let i = 0; i < flawFiles.get(flaw.files.source_file.file).length; i++) {
                    let existingFlaw = flawFiles.get(flaw.files.source_file.file)[i];
                    // check CWE
                    if(flaw.cwe_id == existingFlaw.cwe) {
                        // check (+/- 10 lines)
                        let newFlawLine = parseInt(flaw.files.source_file.line);

                        let existingFlawLine = parseInt(existingFlaw.line);
                        if( (newFlawLine >= (existingFlawLine - 10)) && (newFlawLine <= (existingFlawLine + 10)) ) {
                            isIssueExists = true;
                            break;
                        }
                    }else{
                        isIssueExists = false;
                    }
                }
            }else{
                isIssueExists = false;
            }  
            let title = `${flaw.issue_type} ${vid}`;  
            if(isIssueExists) {
                console.log(`Issue already exists - skipping -- ${title}`);
                continue;
            }else{
                const severityLabel = getSeverityName('static',flaw.severity);
                let labels = `Veracode Pipeline Scan, ${severityLabel}`
                let description = `\n\n**Filename:** ${flaw.files.source_file.file}`;
                description += `\n\n**Line:** ${flaw.files.source_file.line}`;
                description += `\n\n**CWE:** ${flaw.cwe_id} (${flaw.issue_type})`;
                description += '\n\n' + decodeURI(flaw.display_text);
                const issueData ={
                    title,description,labels
                } 
                await createIssue(issueData);
            }
        }
    }catch(error){
        if (error.response) {
            console.log("Error response:", error.response.data);
        } else if (error.request) {
                console.log("No response received:", error.request);
        } else {
            console.log("Error:", error.message);
        }
    }
}

module.exports = pipelineScanIssue;