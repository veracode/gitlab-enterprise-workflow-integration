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
    const pipelines = await fetchAllPipelines(hostName, projectId);

    if (!pipelines || pipelines.length === 0) {
      console.log("No running pipelines found. Nothing to cancel.");
      return;
    }

    // Filter pipelines by name
    const matchingPipelines = pipelines.filter(p => 
      p.name && p.name.toLowerCase() === pipelineName.toLowerCase()
    );

    if (matchingPipelines.length === 0) {
      console.log("No matching pipelines found. Nothing to cancel.");
      return;
    }

    for (const pipeline of matchingPipelines) {
      const pipelineId = pipeline.id;

      // Skip current pipeline itself
      if (pipelineId === Number(currentPipelineId)) {
        console.log(`Skipping current pipeline ${pipelineId}`);
        continue;
      }

      // Convert current pipeline creation time to epoch milliseconds
      const currentEpoch = new Date(currentPipelineCreatedAt).getTime();
      const createdEpoch = new Date(pipeline.created_at).getTime();

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
