const axios = require("axios");
const { appConfig } = require('../config');
const privateToken = process.env.PRIVATE_TOKEN;
const hostName = process.env.CI_SERVER_HOST;
const projectId = process.env.PROJECT_ID;
const labelUrl = `https://${hostName}/api/v4/projects/${encodeURIComponent(projectId)}/labels`;
const issueUrl = `https://${hostName}/api/v4/projects/${encodeURIComponent(projectId)}/issues`;
const wikkiUrl = `https://${hostName}/api/v4/projects/${encodeURIComponent(projectId)}/wikis`;
const headers = {
    headers: {
        "PRIVATE-TOKEN": privateToken,  
    },
}

async function checkLabelExists(veracodeLabel) {
    try {
        const response = await axios.get(labelUrl, headers);
        const labels = response.data;
        const labelExists = labels.some((label) => label.name === veracodeLabel);
        return labelExists;
    } catch (error) {
        console.log("Error fetching labels:", error.response?.data || error.message);
        return false;
    }
}

async function createLabels(labels) {
    try {
        for (const label of labels) {
            const newLabel = {
                name:label.name,
                color: label.color,
                description: label.description
            }
            const response = await axios.post(labelUrl, newLabel, headers);
            console.log("Label created successfully:",response.data.name);
        }
    } catch (error) {
        console.log("Error in creating label:", error.response?.data || error.message);
    }
}

async function createIssue(issue) {
    try {
        const newIssue={
            title: issue.title,
            description: issue.description,
            labels: issue.labels
        }
        const response = await axios.post(issueUrl, newIssue, headers);
        console.log("Issue created successfully:", response.data.title);
    } catch (error) {
        console.error("Error creating issue:", error.response?.data || error.message);
    }
}

async function listExistingOpenIssues(label) {
    let allIssues = [];
    const params = {
        state: "opened", 
        labels: label,
        per_page: 100,
        page: 1
    };
    while (true) {
        try {
            const response = await axios.get(issueUrl, {
                ...headers,
                params: params, 
            });
            const issues = response.data;
            if (issues.length === 0) {
                break;
            }
            allIssues = [...allIssues, ...issues];
            params.page += 1;
        } catch (error) {
            console.error(`Error fetching issues ${issueUrl}:`, error.response?.data || error.message);
            break;
        }
    }
    return allIssues;
}

async function createWikiPage(scanType, projectUrl, formattedContent) {
    let result = {wikiUrl:''};
    try {
        const currentDate = new Date();
        const formattedTimestamp = currentDate.toISOString();
        const reqData = {
            title: `${scanType} Scan Results/${formattedTimestamp}`,
            content: formattedContent
        };
        const response = await axios.post(wikkiUrl, reqData, headers);
        console.log(`Wiki page successfully created under the ${projectUrl} project`);
        result.wikiUrl = `${projectUrl}/-/wikis/${response.data.slug}`;
        return result;
    } catch (error) {
        console.log(`Error while creating wiki page under the ${projectUrl} project`, error.response?.data || error.message);
        return result;
    }
}

async function createComment(projectUrl, mergeRequestId, eventName, commitSha, formattedContent) {
    const infoText = eventName === appConfig().pullRequestEventName ? `merge Request Id:${mergeRequestId}` : `commit sha:${commitSha}`
    try {
        let reqData;
        let url;
        if(eventName === appConfig().pullRequestEventName){
            url = `https://${hostName}/api/v4/projects/${projectId}/merge_requests/${mergeRequestId}/notes`
            reqData = {
                body: formattedContent
            };
        } else {
            url = `https://${hostName}/api/v4/projects/${projectId}/repository/commits/${commitSha}/comments`
            reqData = {
                note: formattedContent
            };
        }
        await axios.post(url, reqData, headers);
        console.log(`Created comment successfully under the ${projectUrl} project for ${infoText}`);
    } catch (error) {
        console.log(`Error while creating comment under the ${projectUrl} project for ${infoText}`, error.response?.data || error.message);
    }
}

async function fetchAllPipelines(hostName, veracodeProjectId) {
    try {
        const url = `https://${hostName}/api/v4/projects/${veracodeProjectId}/pipelines`
        const response = await axios.get(url, {
            ...headers,
            params: { status: "running", per_page: 100 }
        });
        return response.data;
    } catch (error) {
        console.log("Error while fetching all pipelines", error.response?.data || error.message);
        return [];
    }
}

async function getPipelineVariables(hostName, veracodeProjectId, pipelineId) {
    try {
        const url = `https://${hostName}/api/v4/projects/${veracodeProjectId}/pipelines/${pipelineId}/variables`
        const response = await axios.get(url, headers);
        return response.data;
    } catch (error) {
        console.log("Error while fetching pipeline variable", error.response?.data || error.message);
        return [];
    }
}

async function cancelPipeline(hostName, veracodeProjectId, pipelineId) {
    try {
        const url = `https://${hostName}/api/v4/projects/${veracodeProjectId}/pipelines/${pipelineId}/cancel`
        const response = await axios.post(url, {}, headers);
        return response.data;
    } catch (error) {
        console.log("Error while fetching pipeline variable", error.response?.data || error.message);
        return null;
    }
}

module.exports = {checkLabelExists, createLabels, createIssue, listExistingOpenIssues, createWikiPage, createComment, fetchAllPipelines, getPipelineVariables, cancelPipeline}