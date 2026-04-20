const { fetchAllPipelines, getPipelineVariables, cancelPipeline } = require("./utility/service");

const hostName = process.env.CI_SERVER_HOST;
const projectId = process.env.CI_PROJECT_ID;
const pipelineName = process.env.PIPELINE_NAME;
const sourceBranch = process.env.SOURCE_BRANCH;
const currentPipelineId = process.env.CI_PIPELINE_ID;
const currentPipelineCreatedAt = process.env.CI_PIPELINE_CREATED_AT;


async function cancelOldPipeline() {
  try {
    console.log(`Using pipeline name: ${pipelineName}`);
    console.log(`Current branch: ${sourceBranch}`);
    
    // Fetch running pipelines
    const pipelines = await fetchAllPipelines(hostName, projectId, pipelineName);

    if (!pipelines || pipelines.length === 0) {
      console.log("No running pipelines found. Nothing to cancel.");
      return;
    }

    // Find the current pipeline in the list to get its full timestamp with milliseconds
    const currentPipeline = pipelines.find(p => p.id === Number(currentPipelineId));
    const currentPipelineCreatedAtFull = currentPipeline ? currentPipeline.created_at : currentPipelineCreatedAt;

    console.log('#### DEBUG - Current Pipeline Info ####');
    console.log('currentPipelineId:', currentPipelineId);
    console.log('currentPipelineCreatedAt (env):', currentPipelineCreatedAt);
    console.log('currentPipelineCreatedAt (from API):', currentPipelineCreatedAtFull);
    console.log('#### DEBUG - Current Pipeline Info ####');

    for (const pipeline of pipelines) {
      const pipelineId = pipeline.id;

      console.log('#### DEBUG - Cancel Old Pipeline ####');
      console.log('pipelineId:', pipelineId);
      console.log('currentPipelineId:', currentPipelineId);
      console.log('pipeline.created_at:', pipeline.created_at);
      console.log('#### DEBUG - Cancel Old Pipeline ####');

      // Skip current pipeline itself
      if (pipelineId === Number(currentPipelineId)) {
        console.log(`Skipping current pipeline ${pipelineId}`);
        continue;
      }

      // Convert pipeline creation times to epoch milliseconds
      // Use the full timestamp from API for accurate comparison
      const currentEpoch = new Date(currentPipelineCreatedAtFull).getTime();
      const createdEpoch = new Date(pipeline.created_at).getTime();

      console.log('#### DEBUG - Time Comparison ####');
      console.log('currentEpoch:', currentEpoch);
      console.log('createdEpoch:', createdEpoch);
      console.log('Difference (ms):', createdEpoch - currentEpoch);
      console.log('Is createdEpoch > currentEpoch?', createdEpoch > currentEpoch);
      console.log('#### DEBUG - Time Comparison ####');

      // Skip newer pipelines
      if (createdEpoch > currentEpoch) {
        console.log(`Skipping newer pipeline ${pipelineId} created at ${pipeline.created_at}`);
        continue;
      }

      // Get pipeline variables
      const vars = await getPipelineVariables(hostName, projectId, pipelineId)

      const pipelineBranch = vars.find(v => v.key === "SOURCE_BRANCH")?.value;

      if (pipelineBranch === sourceBranch) {
        console.log(`Cancelling older pipeline ${pipelineId} created at ${pipeline.created_at}`);
        await cancelPipeline(hostName, projectId, pipelineId)
      } else {
        console.log(`Pipeline ${pipelineId} branch ${pipelineBranch} does not match current branch ${sourceBranch}, skipping`);
      }
    }
  } catch (error) {
    console.log("Error cancelling pipelines:", error.response?.data || error.message);
  }
}

cancelOldPipeline();
