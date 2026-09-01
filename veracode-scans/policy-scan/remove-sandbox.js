const { veracodeConfig } = require('../../config');
const { getApplicationByName, isProfileExists, getSandboxesByApplicationGuid, deleteResourceById } = require('../../utility/common');

async function removeSandboxScan(apiId, apiKey, sourceBranch, applicationName, brokerMetaData) {
    try {
        if (sourceBranch) {
            const sandboxName = `${veracodeConfig().sandboxScanName}${sourceBranch}`;
            const responseData = await getApplicationByName(apiId, apiKey, applicationName, brokerMetaData);
            const appDetail = isProfileExists(responseData, applicationName);
            const appGuid = appDetail?.veracodeApp?.appGuid;
            const sandboxesResponse = await getSandboxesByApplicationGuid(appGuid, apiId, apiKey, brokerMetaData);
            const sandbox = sandboxesResponse?._embedded?.sandboxes.find((s) => s.name === sandboxName);

            const response = removeSandboxeByUuid(sandbox.guid, appGuid, apiId, apiKey, brokerMetaData);
            console.log(`Response from remove sandbox scan from veracode platform for applicationName ${sandboxName} : ${JSON.stringify(response)}`);
            return response;
        }
        console.log(`remove sandbox scan failed becasue sourceBranch not found`);
    } catch (error) {
        console.log(`error while removing sandbox scan: ${error}`);
    }
}

async function removeSandboxeByUuid(uuid, appGuid, appId, appKey, brokerMetaData) {
    const resource = {
        resourceUri: veracodeConfig().sandboxUri.replace('${appGuid}', appGuid),
        queryValue1: uuid
    };
    const response = await deleteResourceById(appId, appKey, resource, brokerMetaData);
    return response;
}


module.exports = removeSandboxScan;