const fs = require('fs');
const path = require('path');
const { veracodeConfig } = require('../../config');
const { getVeracodeApplication, veracodePolicyVerification } = require('../../utility/common');
const execa = require('execa');
const { exitOnFailure } = require('../../utility/utils');

async function sandboxScan(apiId, apiKey, sourceBranch, policyName, teams, createprofile, buildId, appName, breakBuildOnInvalidPolicy, repoUrl) {
    let resApp;
    try {
        const invalidPolicy = await veracodePolicyVerification(apiId, apiKey, policyName, breakBuildOnInvalidPolicy);
        if (invalidPolicy) {
            exitOnFailure(breakBuildOnInvalidPolicy);  
        }
    } catch (e) {
        console.log(`Error while fetching policy details for ${policyName}`)
    }
    try {
        resApp = await getVeracodeApplication(apiId, apiKey, appName, policyName, teams, createprofile, repoUrl);
    } catch (error) {
        console.log(`Error while retriving application details for ${appName}`, error);
        return;
    }

    const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
    try {
        const artifacts= await fs.promises.readdir(veracodeArtifactsDir);
        console.log(`Artifacts present under ${veracodeArtifactsDir} :- `, artifacts);
    } catch (error) {
        console.log(`Error reading veracode-artifacts directory: ${error}`);
        return;
    }

    try {
        triggerSandboxScan(apiId, apiKey, resApp, veracodeArtifactsDir, sourceBranch, buildId);
    } catch (error) {
        console.log(`Error while executing sandbox scan on ${sourceBranch} branch: `, error);
        return;
    }
}

async function triggerSandboxScan(apiId, apiKey, resApp, artifactFilePath, sourceBranch, buildId) {
    const sandboxName = `${veracodeConfig().sandboxScanName}${sourceBranch}`;
    const args = [
        '-jar', `${__dirname}/api-wrapper-LATEST/VeracodeJavaAPI.jar`,
        '-action', 'UploadAndScanByAppId',
        '-vid', apiId,
        '-vkey', apiKey,
        '-appid', resApp?.appId,
        '-filepath', artifactFilePath,
        '-version', buildId,
        '-sandboxname', sandboxName,
        '-createsandbox', 'true',
        '-scanpollinginterval', '30',
        '-', 'include',
        '-autoscan', 'true',
        '-scanallnonfataltoplevelmodules', 'true',
        '-includenewmodules', 'true',
        '-deleteincompletescan', '2'
    ];

    try {
        const { stdout } = await execa('java', args);
        console.log(`Output from sandbox scan command: ${stdout}`); 
    } catch (error) {
        console.log("Sandbox error : ");
        console.log(error);
    }    
}


module.exports = sandboxScan;