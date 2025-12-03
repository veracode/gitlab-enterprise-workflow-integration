const axios = require("axios");
const crypto = require('crypto');
const cryptoJS = require("crypto-js");
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { veracodeConfig, appConfig } = require('../config');
const authorizationScheme = "VERACODE-HMAC-SHA-256";
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

async function getVeracodeApplication(vid, vkey, applicationName, policyName, teams, createprofile, repoUrl) {
    const responseData = await getApplicationByName(vid, vkey, applicationName);
    const veracodePolicy = await getVeracodePolicyByName(vid, vkey, policyName);
    const policyId = veracodePolicy.policyGuid;
    const profile = isProfileExists(responseData, applicationName);
    if (profile.exists) {
        const existingVeracodePolicy = responseData?._embedded?.applications[0]?.profile?.policies[0]?.guid;
        const applicationGuid = responseData?._embedded?.applications[0]?.guid;
        // Check for the Existing & Policy specified in the config file.
        if (existingVeracodePolicy !== policyId){
            const resource = generateResource(veracodeConfig().applicationUri, applicationName, policyId);
            await updateResource(vid, vkey, resource, applicationGuid);
            return resourceResponse(
                responseData?._embedded?.applications[0]?.id, 
                responseData?._embedded?.applications[0]?.guid, 
                responseData?._embedded?.applications[0]?.oid
            );
        }
        return profile.veracodeApp;
    } else {
        if (createprofile) {
            const resource = {
                resourceUri: veracodeConfig().applicationUri,
                resourceData: {
                    profile: {
                        business_criticality: "HIGH",
                        name: applicationName,
                        policies: [
                            {
                                guid: policyId
                            }
                        ],
                        teams: [],
                        git_repo_url: repoUrl
                    }
                }
            };
            const response = await createResource(vid, vkey, resource);
            const appProfile = response.app_profile_url;
            return {
                'appId': response.id,
                'appGuid': response.guid,
                'oid': appProfile.split(':')[1]
            };
        }
        return { 'appId': -1, 'appGuid': -1, 'oid': -1 };
    }
}

async function getApplicationByName(vid, vkey, applicationName) {
    const resource = {
        resourceUri: veracodeConfig().applicationUri,
        queryAttribute1: 'name',
        queryValue1: encodeURIComponent(applicationName)
    };
    const response = await getResourceByAttribute(vid, vkey, resource);
    console.log(`${appConfig().logPrefix} Response from create profile on veracode platform for applicationName ${applicationName} : ${JSON.stringify(response)}`);
    return response;
}

async function getSandboxesByApplicationGuid(appGuid, appId, appKey) {
    const resource = {
        resourceUri: veracodeConfig().sandboxUri.replace('${appGuid}', appGuid),
        queryAttribute1: '',
        queryValue1: ''
    };
    const response = await getResourceByAttribute(appId, appKey, resource);
    console.log(`${appConfig().logPrefix} Response from retriving sandboxes by application guuid ${appGuid} : ${JSON.stringify(response)}`);
    return response;
}

async function deleteResourceById(vid, vkey, resource) {
    const resourceUri = resource.resourceUri;
    const resourceId = resource.queryValue1;

    const queryUrl = `${resourceUri}/${resourceId}`;
    let host = veracodeConfig().hostName.US;
    if (vid.startsWith('vera01ei-')) {
        host = veracodeConfig().hostName.EU;
        vid = vid.split('-')[1] || '';
        vkey = vkey.split('-')[1] || '';
    }
    const headers = {
        Authorization: calculateAuthorizationHeaderV2({
            id: vid,
            key: vkey,
            host: host,
            url: queryUrl,
            method: 'DELETE',
        }),
    };
    const appUrl = `https://${host}${resourceUri}/${resourceId}`;
    try {
        return await axios.delete(appUrl, { headers });
    } catch (error) {
        console.log('Error while executing delete resource request :');
        console.log(error);
    }
}

function calculateAuthorizationHeaderV2(params) {
    const uriString = params.url;
    const data = `id=${params.id}&host=${params.host}&url=${uriString}&method=${params.method}`;
    const dateStamp = Date.now().toString();
    const nonceBytes = newNonce();
    const dataSignature = calulateDataSignature(params.key, nonceBytes, dateStamp, data);
    const authorizationParam = `id=${params.id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    const header = authorizationScheme + ' ' + authorizationParam;
    return header;
}

function getResourceDetails(vid, vkey, resource) {
    const resourceUri = resource.resourceUri;
    const queryAttribute = resource.queryAttribute1;
    const queryValue = resource.queryValue1;
    const queryAttribute2 = resource.queryAttribute2;
    const queryValue2 = resource.queryValue2;
    var urlQueryParams = queryAttribute !== '' ? `?${queryAttribute}=${queryValue}` : '';
    if (queryAttribute2) {
        urlQueryParams = urlQueryParams + `&${queryAttribute2}=${queryValue2}`;
    }
    let host = veracodeConfig().hostName.US;
    if (vid.startsWith('vera01ei-')) {
        host = veracodeConfig().hostName.EU;
        vid = vid.split('-')[1] || '';
        vkey = vkey.split('-')[1] || '';
    }
    const headers = {
        'Authorization': calculateAuthorizationHeader(vid, vkey, host, resourceUri, urlQueryParams, 'GET')
    };
    const appUrl = `https://${host}${resourceUri}${urlQueryParams}`;
    return {headers, appUrl};
}

async function validateCredential(vid, vkey) {
    const resource = {
        resourceUri: veracodeConfig().selfUserUri,
        queryAttribute1: '',
        queryValue1: '',
      };
    const {headers, appUrl} = getResourceDetails(vid, vkey, resource);
    try {
        const response = await axios.get(appUrl, { headers });
        if (response.data.api_credentials) {
            const expirationDate = response?.data?.api_credentials?.expiration_ts ? new Date(response?.data?.api_credentials?.expiration_ts) : null;
            const currentDate = new Date();
            if (expirationDate && expirationDate > currentDate) return true;
        }
        console.log(`${appConfig().logPrefix} Veracode credentials are invalid or expired.`);
        return false;
    } catch (error) {
        console.log(`${appConfig().logPrefix} Error while validating the veracode credentials : ${error}`);
        return false;
    }
}

async function getResourceByAttribute(vid, vkey, resource) {
    const {headers, appUrl} = getResourceDetails(vid, vkey, resource);
    try {
        const response = await axios.get(appUrl, { headers });
        return response.data;
    } catch (error) {
        console.log(`${appConfig().logPrefix} Error while calling api with resource : ${JSON.stringify(resource)}: ${error}`);
    }
}

function calculateAuthorizationHeader(id, key, hostName, uriString, urlQueryParams, httpMethod) {
    uriString += urlQueryParams;
    let data = `id=${id}&host=${hostName}&url=${uriString}&method=${httpMethod}`;
    let dateStamp = Date.now().toString();
    let nonceBytes = newNonce(nonceSize);
    let dataSignature = calulateDataSignature(key, nonceBytes, dateStamp, data);
    let authorizationParam = `id=${id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    let header = authorizationScheme + " " + authorizationParam;
    return header;
}

function calculateAuthorizationHeaderV2(params) {
    const uriString = params.url;
    const data = `id=${params.id}&host=${params.host}&url=${uriString}&method=${params.method}`;
    const dateStamp = Date.now().toString();
    const nonceBytes = newNonce(nonceSize);
    const dataSignature = calulateDataSignature(params.key, nonceBytes, dateStamp, data);
    const authorizationParam = `id=${params.id},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
    const header = authorizationScheme + ' ' + authorizationParam;
    return header;
}

function newNonce(nonceSize) {
    return crypto.randomBytes(nonceSize).toString('hex').toUpperCase();
}

function calulateDataSignature(apiKeyBytes, nonceBytes, dateStamp, data) {
    let kNonce = computeHashHex(nonceBytes, apiKeyBytes);
    let kDate = computeHashHex(dateStamp, kNonce);
    let kSig = computeHashHex(requestVersion, kDate);
    let kFinal = computeHashHex(data, kSig);
    return kFinal;
}

function computeHashHex(message, key_hex) {
    let key_bits = cryptoJS.enc.Hex.parse(key_hex);
    let hmac_bits = cryptoJS.HmacSHA256(message, key_bits);
    let hmac = hmac_bits.toString(cryptoJS.enc.Hex);
    return hmac;
}

function toHexBinary(input) {
    let binaryValue = cryptoJS.enc.Utf8.parse(input);
    return binaryValue.toString(cryptoJS.enc.Hex);
}


function isProfileExists(responseData, applicationName) {
    if (responseData?.page?.total_elements === 0) {
        console.log(`No Veracode application profile found for ${applicationName}`);
        return { exists: false, veracodeApp: null };
    }
    else {
        for (let i = 0; i < responseData._embedded.applications.length; i++) {
            if (responseData._embedded.applications[i].profile.name.toLowerCase() === applicationName.toLowerCase()) {
                return {
                    exists: true,
                    veracodeApp: {
                        'appId': responseData._embedded.applications[i].id,
                        'appGuid': responseData._embedded.applications[i].guid,
                        'oid': responseData._embedded.applications[i].oid,
                    }
                };;
            }
        }
        console.log(`No Veracode application profile with exact the profile name: ${applicationName}`);
        return { exists: false, veracodeApp: null };
    }
}

async function getVeracodePolicyByName(vid, vkey, policyName) {
    if (policyName !== '') {
        const responseData = await getPolicyByName(vid, vkey, policyName);
        if (responseData.page.total_elements !== 0) {
            for (let i = 0; i < responseData._embedded.policy_versions.length; i++) {
                if (responseData?._embedded?.policy_versions[i]?.name?.toLowerCase() === policyName.toLowerCase()) {
                    return {
                        'policyGuid': responseData._embedded.policy_versions[i].guid,
                    }
                }
            }
        }
    }
    return { 'policyGuid': veracodeConfig().defaultPolicyUuid };
}

async function getPolicyByName(vid, vkey, policyName) {
    const resource = {
        resourceUri: veracodeConfig().policyUri,
        queryAttribute: 'name',
        queryValue: encodeURIComponent(policyName)
    };
    const response = await getResourceByAttribute(vid, vkey, resource);
    return response;
}

async function createResource(vid, vkey, resource) {
    const resourceUri = resource.resourceUri;
    const resourceData = resource.resourceData;
    let host = veracodeConfig().hostName.US;
    if (vid.startsWith('vera01ei-')) {
        host = veracodeConfig().hostName.EU;
        vid = vid.split('-')[1] || '';
        vkey = vkey.split('-')[1] || '';
    }
    const headers = {
        'Authorization': calculateAuthorizationHeader(vid, vkey, host, resourceUri, '', 'POST')
    };
    const appUrl = `https://${host}${resourceUri}`;
    try {
        const response = await axios.post(appUrl, resourceData, { headers });
        // console.debug(`veracode: Response from ${appUrl} : ${response.data}`);
        return response.data;
    } catch (error) {
        console.debug(`veracode: Error while requesting ${appUrl} api : ${error}`);
    }
}

async function getApplicationFindings(appGuid, vid, vkey) {
    const getPolicyFindingsByApplicationResource = {
        resourceUri: `${veracodeConfig().findingsUri}/${appGuid}/findings`,
        queryAttribute1: 'size',
        queryValue1: '1000',
    };

    const findingsResponse = await getResourceByAttribute(vid, vkey, getPolicyFindingsByApplicationResource);

    if (!findingsResponse._embedded) {
        console.log('No Policy scan found, lets look for sandbox scan findings');
        const getSandboxGUID = {
            resourceUri: `${veracodeConfig().findingsUri}/${appGuid}/sandboxes`,
            queryAttribute1: '',
            queryValue1: '',
        };

        const sandboxesResponse = await getResourceByAttribute(vid, vkey, getSandboxGUID);

        if (!sandboxesResponse._embedded) {
            console.log('No Policy scan found and no sandbox scan found.');
            return []
        }
        else {
            const sandboxGuid = sandboxesResponse._embedded.sandboxes[0].guid;
            const getPolicyFindingsBySandboxResource = {
                resourceUri: `${veracodeConfig().findingsUri}/${appGuid}/findings`,
                queryAttribute1: 'context',
                queryValue1: sandboxGuid,
            };

            const findingsResponse = await getResourceByAttribute(vid, vkey, getPolicyFindingsBySandboxResource);

            if (!findingsResponse._embedded) {
                console.log('No Policy scan found and no sandbox scan found.');
                return [];
            }
            else {
                return findingsResponse._embedded.findings;
            }
        }
    }
    else {
        return findingsResponse._embedded.findings;
    }
}

async function isDirExist(dirPath) {
    try {
        return fs.existsSync(dirPath);
    } catch (error) {
        console.debug(`${appConfig().logPrefix} ${dirPath} directory does not exist: ${error}`);
        return false;
    }
}

async function getLatestVersion() {
    const response = await axios.get(`${veracodeConfig().cliLatestVersionUrl}`);
    console.debug(`${appConfig().logPrefix} response from cli version Api: ${JSON.stringify(response.data)}`);
    return response.data;
}

async function downloadAndExtractCli(version, veracodeCliPath) {
    console.debug(`${appConfig().logPrefix} Verifying and downloading the cli if it is not present in the ${veracodeCliPath} location`);

    const cliFileName = `veracode-cli_${version}_linux_x86`;
    const normalizedCliPath = path.normalize(veracodeCliPath);
    const isCliExist = await isDirExist(`${normalizedCliPath}/${cliFileName}`);
    if (isCliExist) {
        console.debug(`${appConfig().logPrefix} ${veracodeCliPath}/${cliFileName} directory exists, skipping downloading cli`);
    } else {
        const cliFile = `${cliFileName}.tar.gz`;
        const downloadUrl = `${veracodeConfig().cliDownloadUrl}${cliFile}`;
        console.debug(`${appConfig().logPrefix} Downloading the cli from ${downloadUrl} url.`);
        try {
            // Downloading CLI
            const response = await axios.get(downloadUrl, { responseType: 'arraybuffer', maxContentLength: Number.MAX_SAFE_INTEGER, maxBodyLength: Number.MAX_SAFE_INTEGER });
            const buffer = Buffer.from(response.data);

            // Define the path to save the downloaded CLI
            const tempZipPath = path.resolve(normalizedCliPath, cliFile);
            fs.writeFileSync(tempZipPath, buffer);

            // Validate the downloaded file
            if (!fs.existsSync(tempZipPath) || fs.statSync(tempZipPath).size === 0) {
                console.error(`${appConfig().logPrefix} Downloaded file is invalid or empty: ${tempZipPath}`);
                return;
            }

            // Ensure the directory exists before extracting
            if (!fs.existsSync(normalizedCliPath)) {
                fs.mkdirSync(normalizedCliPath, { recursive: true });
            }

            // Extract the downloaded tar file
            try {
                execSync(`tar -xzf ${tempZipPath} -C ${normalizedCliPath}`);
                console.debug(`${appConfig().logPrefix} CLI file successfully downloaded and extracted at ${normalizedCliPath}`);
            } catch (error) {
                console.error(`${appConfig().logPrefix} Error during CLI extraction: ${error.message}`);
                throw new Error('CLI extraction failed');
            }

            // Clean up the downloaded tar file
            fs.unlinkSync(tempZipPath);
        } catch (error) {
            console.error(`${appConfig().logPrefix} Error while downloading the cli from ${downloadUrl} url: ${error.message}`);
        }
    }
}



function prettyPrintXml(xmlString) {
    try {
        // const formattedXml = xmlFormatter(xmlString, {
        //     indentation: '  ', // Two spaces for indentation (you can adjust it)
        //     collapseContent: true, // Collapses text nodes
        //     lineSeparator: '\n', // Defines line breaks
        // });

        return xmlString;
    } catch (error) {
        console.error('Error formatting XML:', error);
        return xmlString; // Return the original XML string if formatting fails
    }
}


function setScanResultSuccess(scanResult, message) {
    scanResult.message = message;
    scanResult.status = Status.Success;
    return scanResult;
}

function setScanResultFindings(scanResult, message) {
    scanResult.message = message;
    scanResult.status = Status.Findings;
    return scanResult;
}

function setScanResultError(scanResult, message) {
    scanResult.message = message;
    scanResult.status = Status.Error;
    return scanResult;
}

async function veracodePolicyVerification(vid, vkey, policyName, breakBuildOnInvalidPolicy) {
    let policyStatus = false;
    try {
        if (breakBuildOnInvalidPolicy) {
            if (policyName !== '') {
                const resource = {
                    resourceUri: veracodeConfig().policyUri,
                    queryAttribute1: 'name',
                    queryValue1: encodeURIComponent(policyName),
                    queryAttribute2: 'name_exact',
                    queryValue2: true,
                };

                const response = await getResourceByAttribute(vid, vkey, resource);
                if (response && response?.page?.total_elements != 1) {
                    console.log('Invalid Veracode Policy name.')
                    policyStatus = true;
                }
            } else {
                console.log(`Please Provide Policy Name`)
                policyStatus = true;
            }
            return policyStatus;
        }
        return false;
    } catch (e) {
        throw e;
    }
}

const generateResource = (uri, applicationName, policyId) => {
    return {
        resourceUri: uri,
        resourceData: {
            profile: {
                business_criticality: "HIGH",
                name: applicationName,
                policies: [
                    {
                        guid: policyId
                    }
                ],
                teams: []
            }
        }
    };
}

const resourceResponse = (appId, appGuid, oid) => {
    return {
        appId,
        appGuid,
        oid
    }
}

async function updateResource(vid, vkey, resource, appGuid) {
    const resourceUri = resource.resourceUri;
    const resourceData = resource.resourceData;
    const host = veracodeConfig().hostName.US;
    const queryParameter   = `${resourceUri}/${appGuid}`;
    if (vid.startsWith('vera01ei-')) {
        host = veracodeConfig().hostName.EU;
        vid = vid.split('-')[1] || '';
        vkey = vkey.split('-')[1] || '';
    }
    const headers = {
        'Authorization': calculateAuthorizationHeader(vid, vkey, host, queryParameter, '', 'PUT')
    };
    const appUrl = `https://${host}${resourceUri}/${appGuid}`;
    try {
        const response = await axios.put(appUrl, resourceData, { headers });
        return response.data;
    } catch (error) {
        console.debug(`veracode: Error while requesting ${appUrl} api : ${error}`);
    }
}

module.exports = {
    getVeracodeApplication,
    getApplicationByName,
    getResourceByAttribute,
    isProfileExists,
    getSandboxesByApplicationGuid,
    deleteResourceById,
    getApplicationFindings,
    veracodePolicyVerification,
    getLatestVersion,
    downloadAndExtractCli,
    setScanResultError,
    setScanResultSuccess,
    setScanResultFindings,
    setScanResultError,
    validateCredential
};