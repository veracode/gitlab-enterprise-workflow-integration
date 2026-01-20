const pipelineScan = require('./veracode-scans/pipeline-scan/pipeline');
const policyScan = require('./veracode-scans/policy-scan/policy');
const removeSandboxScan = require('./veracode-scans/policy-scan/remove-sandbox');
const sandboxScan = require('./veracode-scans/policy-scan/sandbox');
const scaScan = require('./veracode-scans/sca-scan/sca-scan');
const iacScan = require('./veracode-scans/iac-scan/iac-scan');

async function veracodeScan() {
    const projectName = process.env.PROJECT_NAME;
    const executePipeline = process.env.EXECUTE_PIPELINE;
    const executePolicy = process.env.EXECUTE_POLICY;
    const executeSandbox = process.env.EXECUTE_SANDBOX;
    const executeRemoveSandbox = process.env.EXECUTE_REMOVE_SANDBOX;
    const executeSca = process.env.EXECUTE_SCA;
    const executeIac = process.env.EXECUTE_IAC;
    const breakBuildOnFinding = process.env.BREAK_BUILD_ON_FINDING || false;
    const breakBuildOnError = process.env.BREAK_BUILD_ON_ERROR || false;
    const sourceProjectId = process.env.PROJECT_ID;
    const policyName = process.env.POLICY_NAME || '';
    const createProfile = true;
    const sourceRepoCloneUrl = process.env.CLONE_URL;
    const scaAgenToken = process.env.VERACODE_AGENT_TOKEN;
    const scaUrl = process.env.VERACODE_SRCCLR_URL;
    const sourceBranch = process.env.SOURCE_BRANCH;
    const appProfileName = process.env.PROFILE_NAME;
    const filterMitigatedFlaws = process.env.FILTER_MITIGATED_FLAWS || true;
    const createIssue = process.env.CREATE_ISSUE || false;

    const ciPipelineId = process.env.CI_PIPELINE_ID;

    const apiId = process.env.VERACODE_API_ID;
    const appKey = process.env.VERACODE_API_KEY;

    const userErrorMessage = process.env.ERROR_MESSAGE;
    const breakBuildOnInvalidPolicy = process.env.BREAK_BUILD_ON_INVALID_POLICY || false;

    const repoUrl = process.env.PROJECT_URL;
    const debug = process.env.DEBUG;

    if (executePipeline) {
        console.log(`Executing pipeline scan on ${projectName} repo for ${sourceBranch} branch`);
        await pipelineScan(apiId, appKey, appProfileName, filterMitigatedFlaws, breakBuildOnFinding, breakBuildOnError, userErrorMessage, policyName, breakBuildOnInvalidPolicy, createIssue, debug);
    }
    if (executeSandbox) {
        console.log(`Executing sandbox scan on ${projectName} repo for ${sourceBranch} branch`);
        sandboxScan(apiId, appKey, sourceBranch, policyName, '', createProfile, ciPipelineId, appProfileName, breakBuildOnInvalidPolicy, repoUrl, debug)
    }
    if (executePolicy) {
        console.log(`Executing policy scan on ${projectName} repo for ${sourceBranch} branch`);
        await policyScan(apiId, appKey, appProfileName, ciPipelineId, policyName, '', createProfile, breakBuildOnFinding, breakBuildOnError, userErrorMessage, breakBuildOnInvalidPolicy, createIssue, repoUrl, debug);
    }
    if (executeRemoveSandbox) {
        console.log(`Executing removed sandbox scan on ${projectName} repo for ${sourceBranch} branch`);
        removeSandboxScan(apiId, appKey, sourceBranch, appProfileName)
    }
    if (executeSca) {
        console.log(`Executing sca scan on ${projectName} repo for ${sourceBranch} branch`);
        await scaScan(sourceRepoCloneUrl, scaAgenToken, scaUrl, sourceBranch, breakBuildOnFinding, breakBuildOnError, userErrorMessage, createIssue, debug);
    }
    if (executeIac) {
        console.log(`Executing iac scan on ${projectName} repo for ${sourceBranch} branch`);
        await iacScan(sourceBranch, breakBuildOnFinding, breakBuildOnError, userErrorMessage, debug)
    }
}
veracodeScan();
