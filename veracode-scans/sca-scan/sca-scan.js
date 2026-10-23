const { execSync } = require('child_process');
const path = require('path');
const { attacheResult, exitOnFailure, updateErrorMessage } = require('../../utility/utils');
const scaScanIssue = require('../../veracode-issues/scaScanIssue');
const displayScanResult = require('../../displayScanResult');
const { updateCommitStatus } = require('../../utility/service');

async function scaScan(clone_url, scaAgenToken, scaUrl, sourceBranch, breakBuildOnFinding, breakBuildOnError, userErrorMessage, createIssue, debug, brokerMetaData, commitSha, pipelineName, ciPipelineUrl) {
  try {
    // Check if broker client is available and set up the download URL accordingly
    let downloadUrl = 'https://download.sourceclear.com/ci.sh';
    let curlHeaders = '';
    const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
    if (!fs.existsSync(veracodeArtifactsDir)) {
      fs.mkdirSync(veracodeArtifactsDir, { recursive: true });
    }
    const scaScanJsonPath = path.join(veracodeArtifactsDir, 'scaScan.json');

    if (brokerMetaData) {
      const brokerData = JSON.parse(brokerMetaData);
      const brokerClientUrl = brokerData?.clientUrl;
      if (brokerClientUrl) {
        downloadUrl = `${brokerClientUrl}/proxy/download.sourceclear.com/ci.sh`;
        curlHeaders = '-H "X-Target-Hostname: download.sourceclear.com"';
      }
    }

    let command = `curl -sSL ${curlHeaders} ${downloadUrl} | sh -s -- scan --url ${clone_url} --ref ${sourceBranch} --json=${scaScanJsonPath} --show-cli --recursive --allow-dirty`;
    if(debug === "true")
      command += ' --debug';
    const output = execSync(command, { encoding: 'utf-8', env: { ...process.env, SRCCLR_API_TOKEN: scaAgenToken, SRCCLR_API_URL: scaUrl }, maxBuffer: 1024 * 1024 * 10 });
    const jsonFileContent = fs.readFileSync(scaScanJsonPath, 'utf-8');
    const parsedOutput = JSON.parse(jsonFileContent);
    const scanRecord = parsedOutput.records.find((record) => record?.metadata?.recordType === "SCAN");
    if (!scanRecord || (scanRecord.vulnerabilities.length === 0 && scanRecord.libraries.length === 0 && scanRecord.unmatchedLibraries.length === 0 && scanRecord.vulnMethods.length === 0)) {
      await displayScanResult([]);
      console.log(`Veracode SCA scan executed successfully.`);
      console.log(output);
      await updateCommitStatus(commitSha, 'success', pipelineName, ciPipelineUrl, `${pipelineName} no findings`, debug);
    } else {
      await displayScanResult(parsedOutput.records);
      if (createIssue) {
        await scaScanIssue(parsedOutput);
      }
      console.log(`Veracode SCA scan executed successfully.`);
      console.log(output);
      await updateCommitStatus(commitSha, 'failed', pipelineName, ciPipelineUrl, `${pipelineName} findings`, debug);
      exitOnFailure(breakBuildOnFinding);
    }
  } catch (error) {
    error = updateErrorMessage(breakBuildOnError, userErrorMessage, error.message);
    console.error(`Error occurred during SCA scan: ${error}`);
    await updateCommitStatus(commitSha, 'failed', pipelineName, ciPipelineUrl, `${pipelineName} failed`, debug);
    exitOnFailure(breakBuildOnError);
  }
}

module.exports = scaScan;