const { updateCommitStatus } = require("./service");

const commitSha = process.env.COMMIT_SHA;
const state = 'running';
const pipelineName = process.env.PIPELINE_NAME ;
const ciPipelineUrl = process.env.CI_PIPELINE_URL;
const description = process.env.PIPELINE_NAME+' started';

async function updateStatus() {
  console.log('#### DEBUG - Update Commit Status ####');
  console.log('commitSha:', commitSha);
  console.log('state:', state);
  console.log('pipelineName:', pipelineName);
  console.log('ciPipelineUrl:', ciPipelineUrl);
  console.log('description:', description);
  console.log('#### DEBUG - Update Commit Status ####');
  try {
    if (!commitSha) {
      console.log("Error: Commit SHA not found. Please set CI_COMMIT_SHA or COMMIT_SHA environment variable.");
      process.exit(0);
    }

    if (!ciPipelineUrl) {
      console.log("Error: CI_PIPELINE_URL not found.");
      process.exit(0);
    }
    
    if (pipelineName && pipelineName.includes('Sandbox Scan')) {
      console.log("No Need to update MR status for a Sandbox Scan");
      process.exit(0);
    }

    if (pipelineName && pipelineName.includes('Policy Scan')) {
      console.log("No Need to update MR status for a Policy Scan");
      process.exit(0);
    }

    console.log(`Updating commit status for SHA: ${commitSha}`);
    console.log(`State: ${state}`);
    console.log(`Pipeline Name: ${pipelineName}`);
    console.log(`Description: ${description}`);

    const result = await updateCommitStatus(commitSha, state, pipelineName, ciPipelineUrl, description);
    
    if (!result) {
      console.log("MR couldn't be updated");
      //process.exit(1);
    }

    console.log("Commit status updated successfully");
  } catch (error) {
    console.log("MR couldn't be updated", error.message);
    //process.exit(1);
  }
}

updateStatus();
