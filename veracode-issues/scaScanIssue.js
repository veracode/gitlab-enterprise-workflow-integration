
const {getScaIssueDetails} = require('../utility/utils');
const {checkLabelExists, createIssue, listExistingOpenIssues, createLabels} = require('../utility/service');
const { VERACODE_SCA_LABEL, VERACODE_FLAW_LABELS } = require('../utility/labels');

async function scaScanIssue(scaResJson) {
    try{
        const librariesWithIssues = {};
        const vulnerabilities = scaResJson.records[0].vulnerabilities;
        const libraries = scaResJson.records[0].libraries;
        for(const vulnerability of vulnerabilities){
            const libref = vulnerability.libraries[0]._links.ref;
            const libId = libref.split('/')[4];
            const library = libraries[libId];
            const details = getScaIssueDetails(vulnerability,library);
            const libWithIssues = librariesWithIssues[libId] || {library,issues:[]};
            libWithIssues.issues.push(details);
            librariesWithIssues[libId] = libWithIssues;
        }
        if (Object.keys(librariesWithIssues).length > 0) {
            const isLabelExist = await checkLabelExists(VERACODE_SCA_LABEL.name);
            if(!isLabelExist){
                await createLabels([...Object.values(VERACODE_FLAW_LABELS),VERACODE_SCA_LABEL]);
            }else{
                console.log("Labels already exist");
            }
            let isCreateIssue = true;
            let openIssueTitle;
            const existingOpenIssues = await listExistingOpenIssues("Veracode SCA Scan");
            for (const key in librariesWithIssues) {
                const issueLength = Object.keys(librariesWithIssues[key]['issues']).length;
                for ( let i = 0; i < issueLength; i++ ){
                    const issueTitle = librariesWithIssues[key]['issues'][i]['title'];
                    if(existingOpenIssues.length > 0){
                        for (let j = 0; j < existingOpenIssues.length; j++){
                            openIssueTitle = existingOpenIssues[j]['title'];
                            if ( issueTitle == openIssueTitle ){
                                isCreateIssue = false;
                                break;
                            }else{
                                isCreateIssue = true;
                            }
                        }
                    }
                    if(isCreateIssue){  
                        await createIssue(librariesWithIssues[key]['issues'][i]);
                    }else{
                        console.log('Issue already exists - skipping ---- '+openIssueTitle)
                    }
                }
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

module.exports = scaScanIssue;