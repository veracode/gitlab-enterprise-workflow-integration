const fs = require('fs');
const path = require('path');
const { exitOnFailure, updateErrorMessage, uploadArtifact } = require('../../utility/utils'); 
const execa = require('execa');
const displayScanResult = require('../../displayScanResult');

async function iacScan(sourceBranch, breakBuildOnFinding, breakBuildOnError, userErrorMessage, debug) { 
  const veracodeDir = path.dirname(require.main.filename);
  const veracodeCliPath = path.resolve(veracodeDir, 'veracode-cli');
  const veracodeExecutable = path.join(veracodeCliPath, 'veracode');
  const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
  console.log("Scan Started");
  let sourcePath;
  
  try {
    sourcePath = resolveSourcePath();
  } catch (err) {
    console.error('Failed to resolve source path:', err.message);
    process.exit(1);
  }
  
  try {
    await execa(
      veracodeExecutable,
      [
        'scan',
        '--source', sourcePath,
        '--type', 'directory',
        '--format', 'json',
        '--output', 'results.json',
        ...(debug === "true" ? ['--verbose'] : [])
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
        '--source', sourcePath,
        '--type', 'directory',
        '--format', 'table',
        '--output', 'results.txt',
        ...(debug === "true" ? ['--verbose'] : [])
      ],
      {
        reject: false,
        stderr: 'inherit',
        stdout: 'inherit',
        env: {
          VERACODE_API_KEY_ID: process.env.VERACODE_API_ID,
          VERACODE_API_KEY_SECRET: process.env.VERACODE_API_KEY
        }
      }
    );

  } catch (error) {
    console.log("Error while executing IAC scan :");
    console.log(error);
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


function resolveSourcePath() {
  const cloneRoot = path.resolve(process.cwd(), 'clonePath');

  // Check clonePath exists
  if (!fs.existsSync(cloneRoot)) {
    throw new Error(
      `clonePath directory not found at ${cloneRoot}. ` +
      `Make sure the repository was cloned before running the scan.`
    );
  }

  // Read directories safely
  const entries = fs.readdirSync(cloneRoot, { withFileTypes: true });
  const repoDirs = entries.filter(entry => entry.isDirectory());

  // Validate repo presence
  if (repoDirs.length === 0) {
    throw new Error(
      `No repository directory found inside clonePath (${cloneRoot}). ` +
      `Git clone may have failed.`
    );
  }

  // Warn if multiple repos (optional)
  if (repoDirs.length > 1) {
    console.warn(
      `Multiple repositories found in clonePath. ` +
      `Using the first one: ${repoDirs[0].name}`
    );
  }

  // Resolve final path
  const sourcePath = path.join(cloneRoot, repoDirs[0].name);

  // Final sanity check
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Resolved source path does not exist: ${sourcePath}`);
  }

  console.log('Using source path:', sourcePath);
  return sourcePath;
}

module.exports = iacScan;
