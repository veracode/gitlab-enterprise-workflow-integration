const { updateCommitStatus } = require("./service");

const commitSha = process.env.COMMIT_SHA;
const pipelineName = process.env.PIPELINE_NAME;
const ciPipelineUrl = process.env.CI_PIPELINE_URL;
const debug = process.env.ENABLE_DEBUG === "true";

const EXCLUDED_SCANS = ['Sandbox Scan', 'Policy Scan'];

async function updateStatus() {
  const state = 'running';
  const description = `${pipelineName} started`;

  if (debug) {
    console.log('#### DEBUG - Update Commit Status ####');
    console.log({ commitSha, state, pipelineName, ciPipelineUrl, description });
    console.log('#### DEBUG - Update Commit Status ####');
  }

  try {
    if (!commitSha) {
      console.log("Error: Commit SHA not found. Please set CI_COMMIT_SHA or COMMIT_SHA environment variable.");
      process.exit(0);
    }

    if (!ciPipelineUrl) {
      console.log("Error: CI_PIPELINE_URL not found.");
      process.exit(0);
    }

    if (EXCLUDED_SCANS.some(scan => pipelineName?.includes(scan))) {
      console.log(`No need to update MR status for ${pipelineName}`);
      process.exit(0);
    }

    await updateCommitStatus(commitSha, state, pipelineName, ciPipelineUrl, description, debug);
    
  } catch (error) {
    console.log("updateStatus - MR couldn't be updated", error.message);
  }
}

updateStatus();