const { createWikiPage, createComment } = require('./utility/service');
const { scaResult, pipelineResult, policyResult, iacResult } = require('./utility/utils');
const { appConfig } = require('./config');
async function displayScanResult(scanResult, warningMessage = "") {
    const executePipeline = process.env.EXECUTE_PIPELINE;
    const executeSca = process.env.EXECUTE_SCA;
    const executeIac = process.env.EXECUTE_IAC;
    const projectUrl = process.env.PROJECT_URL;
    const commitSha = process.env.COMMIT_SHA;
    const mergeRequestId = process.env.MERGE_REQUEST_IID;
    const eventName = process.env.EVENT_NAME;
    const scanType = executeSca ? 'SCA' : executeIac ? 'IaC' : executePipeline ? 'Pipeline' : 'Policy'
    if (eventName === appConfig().pullRequestEventName || eventName === appConfig().pushEventName) {
        try {
            if ((scanType === "IaC" && Object.entries(scanResult).length > 0) || scanResult.length > 0) {
                let formattedContent = scanType === 'SCA' ? scaResult(scanResult[0]) : scanType === 'Pipeline' ? pipelineResult(scanResult) : scanType === 'IaC' ? iacResult(scanResult) : policyResult(scanResult);
                const wikiContent = `${scanType} Scan completed. :white_check_mark:\n\n` + formattedContent;
                const createWikiResponse = await createWikiPage(scanType, projectUrl, wikiContent);
                const commentContent = createWikiResponse.hasOwnProperty('wikiUrl') && createWikiResponse?.wikiUrl !== "" ? `<a href=${createWikiResponse.wikiUrl} target="_blank">${scanType} Scan completed.</a> :white_check_mark:\n\n` + formattedContent : `${scanType} Scan completed. :white_check_mark:\n\n` + formattedContent;
                await createComment(projectUrl, mergeRequestId, eventName, commitSha, commentContent);
            } else {
                let commentContent = "";
                if (warningMessage) {
                    commentContent = `${scanType} Scan completed. :warning:\n\n` + `${warningMessage}\n`;
                } else {
                    commentContent = `${scanType} Scan completed. :white_check_mark:\n\n` + 'No Vulnerability found.\n';
                }
                await createComment(projectUrl, mergeRequestId, eventName, commitSha, commentContent);

            }
            console.log(`Successfully displaying ${scanType} scan result`);
        } catch (error) {
            console.log(`Error encountered while displaying ${scanType} scan result`, error.response?.data || error.message);
        }
    }
}

module.exports = displayScanResult;