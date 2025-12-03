const { getApplicationFindings } = require('../utility/common');
const { VERACODE_STATIC_LABELS, VERACODE_FLAW_LABELS } = require('../utility/labels');
const { listExistingOpenIssues, checkLabelExists, createLabels, createIssue } = require('../utility/service');
const { parseVeracodeFlawID, getSeverityName, getVeracodeFlawID } = require('../utility/utils');
async function policyScanIssue(applicationGuid, apiId, apiKey) {
    try{
        const flawData = await getApplicationFindings(applicationGuid, apiId, apiKey);
        const isLabelExist = await checkLabelExists(VERACODE_STATIC_LABELS[1].name);
        const existingFlaws = {};
        if(!isLabelExist){
            await createLabels([...Object.values(VERACODE_FLAW_LABELS), ...VERACODE_STATIC_LABELS]);
        }else{
            console.log("Labels already exist");
        }
        const existingOpenIssues = await listExistingOpenIssues("Veracode Policy Scan");
        existingOpenIssues.forEach(issue => {
            let flawID = getVeracodeFlawID(issue.title);
            // Map using VeracodeFlawID as index, for easy searching.  Line # for simple flaw matching
            if(flawID === null){
                console.log(`Flaw \"${issue.title}\" has no Veracode Flaw ID, ignored.`)
            } else {
                const flawNum = parseVeracodeFlawID(flawID).flawNum;
                existingFlaws[parseInt(flawNum)] = true;
            }
        });
        for(const flaw of flawData) {
            let vid = `[VID:${flaw.issue_id}]`;
             // check for mitigation
            if(flaw.finding_status.resolution_status == 'APPROVED') {   
                console.log('Flaw mitigated, skipping import');
                continue;
            }
            let title = `${flaw.finding_details.cwe.name} ('${flaw.finding_details.finding_category.name}') ${vid}`;  
            if(existingFlaws[flaw.issue_id]) {
                console.log(`Issue already exists - skipping -- ${title}`);
                continue;
            }else{
                const severityLabel = getSeverityName('static',flaw.finding_details.severity);
                let labels = `Veracode Policy Scan, ${severityLabel}`
                let description = `\n\n**Filename:** ${flaw.finding_details.file_name}`;
                description += `\n\n**Line:** ${flaw.finding_details.file_line_number}`;
                description += `\n\n**CWE:** ${flaw.finding_details.cwe.id} (${flaw.finding_details.cwe.name} ('${flaw.finding_details.finding_category.name}'))`;
                description += '\n\n' + decodeURI(flaw.description);
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

module.exports = policyScanIssue;