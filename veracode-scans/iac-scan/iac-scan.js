const fs = require('fs');
const path = require('path');
const { exitOnFailure, updateErrorMessage, uploadArtifact } = require('../../utility/utils'); 
const execa = require('execa');
const displayScanResult = require('../../displayScanResult');

async function iacScan(clone_url, sourceBranch, breakBuildOnFinding, breakBuildOnError, userErrorMessage) { 
  const veracodeDir = path.dirname(require.main.filename);
  const veracodeCliPath = path.resolve(veracodeDir, 'veracode-cli');
  const veracodeExecutable = path.join(veracodeCliPath, 'veracode');
  const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
  console.log("Scan Started");
  try {
    await execa(
      veracodeExecutable,
      [
        'scan',
        '--source', clone_url,
        '--type', 'repo',
        '--format', 'json',
        '--output', 'results.json',
        '--verbose'
      ],
      {
        reject: false,
        env: {
          VERACODE_API_KEY_ID: process.env.VERACODE_API_ID,
          VERACODE_API_KEY_SECRET: process.env.VERACODE_API_KEY
        }
      }
    );

    await execa(
      veracodeExecutable,
      [
        'scan',
        '--source', clone_url,
        '--type', 'repo',
        '--format', 'table',
        '--output', 'results.txt',
        '--verbose'
      ],
      {
        reject: false,
        env: {
          VERACODE_API_KEY_ID: process.env.VERACODE_API_ID,
          VERACODE_API_KEY_SECRET: process.env.VERACODE_API_KEY
        }
      }
    );

  } catch (error) {
    console.log("Scan failed due to invalid credentials.")
  } 

  try {
    console.log('Listing files in Veracode directory...');
    const jsonOutput = fs.readFileSync(`${veracodeDir}/results.json`, "utf8")
    const tableOutput = fs.readFileSync(`${veracodeDir}/results.txt`, "utf8");
    let resultsJSON = JSON.parse(jsonOutput.toString());
    if (jsonOutput?.vulnerabilities?.matches?.length == 0 && !jsonOutput["policy-results"][0].failures) {
      console.log(tableOutput);
      console.log(`Veracode IAC scan executed successfully. No Vulnerabilities found !!`);
    } else {
      await uploadArtifact(veracodeArtifactsDir,"IacScan","IacScan.json",JSON.stringify(resultsJSON, null, 2));
      console.log(`Vulnerability detected in the repository !!`);
      console.error(tableOutput);
      await displayScanResult(resultsJSON);
      exitOnFailure(breakBuildOnError);
    }
  } catch (error) {
    console.log(breakBuildOnError)
    error = updateErrorMessage(breakBuildOnError, userErrorMessage, error.message);
    console.error(`Error occurred during IAC scan: ${error}`);
    exitOnFailure(breakBuildOnError);
  }
}

module.exports = iacScan;