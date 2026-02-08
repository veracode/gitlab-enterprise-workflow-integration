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
        
        // For merge requests, check if a matching comment already exists
        if(eventName === appConfig().pullRequestEventName){
            // Extract scan type and expected patterns from the new content
            const contentLines = formattedContent.split('\n');
            const firstLine = contentLines[0] || '';
            
            // Extract scan type from first line (e.g., "Pipeline Scan completed." or "<a>Pipeline Scan completed.</a>")
            const scanTypeMatch = firstLine.match(/(\w+)\s+Scan\s+completed/);
            const scanType = scanTypeMatch ? scanTypeMatch[1] : '';
            
            // Expected scan message patterns (these appear in the content)
            const expectedPatterns = [
                '**Veracode IaC/Secrets Scan found vulnerabilities/misconfigurations/secrets**',
                '**Veracode SCA Scan found vulnerabilities**',
                '**Veracode Static Scan found flaws**'
            ];
            
            // Check if content contains Veracode image and one of the expected patterns
            const hasVeracodeImage = formattedContent.includes('![Veracode]') || formattedContent.includes('veracodePlatformLogoSmall.png');
            const hasExpectedPattern = expectedPatterns.some(pattern => formattedContent.includes(pattern));
            
            // Only check for existing comments if we have a valid pattern
            if (scanType && hasVeracodeImage && hasExpectedPattern) {
                try {
                    // Fetch all notes for this merge request
                    const notesUrl = `https://${hostName}/api/v4/projects/${projectId}/merge_requests/${mergeRequestId}/notes`;
                    let allNotes = [];
                    let page = 1;
                    
                    while (true) {
                        const response = await axios.get(notesUrl, {
                            ...headers,
                            params: {
                                per_page: 100,
                                page: page
                            }
                        });
                        
                        const notes = response.data;
                        if (notes.length === 0) break;
                        
                        allNotes = [...allNotes, ...notes];
                        
                        const totalPages = parseInt(response.headers['x-total-pages'] || '1');
                        if (page >= totalPages) break;
                        page++;
                    }
                    
                    // Find matching comment by checking:
                    // 1. First line contains scan type + "Scan completed"
                    // 2. Contains Veracode image
                    // 3. Contains one of the expected scan message patterns
                    const matchingNote = allNotes.find(note => {
                        if (!note.body) return false;
                        
                        const noteLines = note.body.split('\n');
                        const noteFirstLine = noteLines[0] || '';
                        
                        // Check if first line matches scan type pattern
                        const noteScanTypeMatch = noteFirstLine.match(/(\w+)\s+Scan\s+completed/);
                        const noteScanType = noteScanTypeMatch ? noteScanTypeMatch[1] : '';
                        
                        // Check if note contains Veracode image
                        const noteHasImage = note.body.includes('![Veracode]') || note.body.includes('veracodePlatformLogoSmall.png');
                        
                        // Check if note contains one of the expected patterns
                        const noteMatchesPattern = expectedPatterns.some(pattern => note.body.includes(pattern));
                        
                        // Match if scan type matches, has image, and matches pattern
                        return noteScanType === scanType && noteHasImage && noteMatchesPattern;
                    });
                    
                    if (matchingNote) {
                        // Update existing comment
                        const updateUrl = `https://${hostName}/api/v4/projects/${projectId}/merge_requests/${mergeRequestId}/notes/${matchingNote.id}`;
                        reqData = {
                            body: formattedContent
                        };
                        await axios.put(updateUrl, reqData, headers);
                        console.log(`Updated existing comment (note ID: ${matchingNote.id}) under the ${projectUrl} project for ${infoText}`);
                        return;
                    }
                } catch (error) {
                    console.log(`Error while checking for existing comments, will create new one:`, error.response?.data || error.message);
                    // Continue to create new comment if check fails
                }
            }
            
            // Create new comment (either no match found or not a merge request with expected pattern)
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

async function fetchAllPipelines(hostName, veracodeProjectId, pipelineName) {
    let pipelines = [];
    let page = 1;
    while(page) {
        try {
            const url = `https://${hostName}/api/v4/projects/${veracodeProjectId}/pipelines`
            const response = await axios.get(url, {
                ...headers,
                params: {
                    status: "running", 
                    name: pipelineName,
                    per_page: 100,
                    page
                }
            });
            pipelines.push(...response.data);
            page = Number(response.headers['x-next-page']);
        } catch (error) {
            console.log("Error while fetching all pipelines", error.response?.data || error.message);
            break;
        }
    }
    return pipelines;
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

async function updateCommitStatus(MR_SHA, STATE, PIPELINE_NAME, CI_PIPELINE_URL, DESCRIPTION) {
    console.log('#### DEBUG - Update Commit Status ####');
    console.log('MR_SHA:', MR_SHA);
    console.log('STATE:', STATE);
    console.log('PIPELINE_NAME:', PIPELINE_NAME);
    console.log('CI_PIPELINE_URL:', CI_PIPELINE_URL);
    console.log('DESCRIPTION:', DESCRIPTION);
    console.log('hostName:', hostName);
    console.log('projectId:', projectId);
    console.log('#### DEBUG - Update Commit Status ####');
    try {
        const url = `https://${hostName}/api/v4/projects/${projectId}/statuses/${MR_SHA}`;
        const formData = new URLSearchParams();
        formData.append('state', STATE);
        formData.append('name', PIPELINE_NAME);
        formData.append('target_url', CI_PIPELINE_URL);
        formData.append('description', DESCRIPTION);
        
        const response = await axios.post(url, formData.toString(), {
            headers: {
                ...headers.headers,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        
        if (response.status >= 200 && response.status < 300) {
            console.log("Commit status updated successfully");
            return response.data;
        } else {
            console.error("MR couldn't be updated");
            return null;
        }
    } catch (error) {
        console.error("MR couldn't be updated", error.response?.data || error.message);
        return null;
    }
}

// Helper function to calculate similarity between two strings (simple Levenshtein-like)
function calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    if (longer.length === 0) return 1.0;
    
    const distance = levenshteinDistance(longer.toLowerCase(), shorter.toLowerCase());
    return (longer.length - distance) / longer.length;
}

// Simple Levenshtein distance calculation
function levenshteinDistance(str1, str2) {
    const matrix = [];
    for (let i = 0; i <= str2.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
        matrix[0][j] = j;
    }
    for (let i = 1; i <= str2.length; i++) {
        for (let j = 1; j <= str1.length; j++) {
            if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    return matrix[str2.length][str1.length];
}

async function getSourceFilePath(filePath, branch, projectUrl, lineNumber = null) {
    try {
        if (!filePath || !branch || !projectUrl) {
            console.log("Error: Missing required parameters for getSourceFilePath");
            return null;
        }

        // Extract filename from the path
        const fileName = filePath.split('/').pop() || filePath.split('\\').pop();
        const normalizedFilePath = filePath.startsWith('/') ? filePath.substring(1) : filePath;
        
        console.log('#### Debug - getSourceFilePath - Fuzzy Search ####');
        console.log('Searching for file:', fileName);
        console.log('Original path:', filePath);
        console.log('Branch:', branch);
        console.log('#### Debug - getSourceFilePath - Fuzzy Search ####');

        // Get repository tree recursively to search for files
        let foundFilePath = null;
        try {
            const treeUrl = `https://${hostName}/api/v4/projects/${encodeURIComponent(projectId)}/repository/tree`;
            let allFiles = [];
            let page = 1;
            const perPage = 100;

            // Fetch all files recursively
            while (true) {
                const response = await axios.get(treeUrl, {
                    ...headers,
                    params: {
                        ref: branch,
                        recursive: true,
                        per_page: perPage,
                        page: page
                    }
                });

                const files = response.data.filter(item => item.type === 'blob');
                allFiles = allFiles.concat(files);

                // Check if there are more pages
                const totalPages = parseInt(response.headers['x-total-pages'] || '1');
                if (page >= totalPages) break;
                page++;
            }

            console.log(`Found ${allFiles.length} files in repository`);

            // First, try exact match
            let exactMatch = allFiles.find(file => 
                file.path === normalizedFilePath || 
                file.path.endsWith(normalizedFilePath) ||
                file.path === filePath
            );

            if (exactMatch) {
                foundFilePath = exactMatch.path;
                console.log(`Exact match found: ${foundFilePath}`);
            } else {
                // Try to find by filename
                let filenameMatches = allFiles.filter(file => 
                    file.name === fileName || 
                    file.name.toLowerCase() === fileName.toLowerCase()
                );

                if (filenameMatches.length === 1) {
                    foundFilePath = filenameMatches[0].path;
                    console.log(`Single filename match found: ${foundFilePath}`);
                } else if (filenameMatches.length > 1) {
                    // Multiple files with same name - use fuzzy matching on path
                    let bestMatch = null;
                    let bestScore = 0;

                    for (const file of filenameMatches) {
                        // Calculate similarity between original path and found path
                        const pathSimilarity = calculateSimilarity(normalizedFilePath, file.path);
                        if (pathSimilarity > bestScore) {
                            bestScore = pathSimilarity;
                            bestMatch = file;
                        }
                    }

                    if (bestMatch && bestScore > 0.3) { // Threshold for similarity
                        foundFilePath = bestMatch.path;
                        console.log(`Fuzzy match found (score: ${bestScore.toFixed(2)}): ${foundFilePath}`);
                    } else {
                        // Use the first match if no good fuzzy match
                        foundFilePath = filenameMatches[0].path;
                        console.log(`Using first filename match: ${foundFilePath}`);
                    }
                } else {
                    // No exact filename match - try fuzzy search on all files
                    let bestMatch = null;
                    let bestScore = 0;

                    for (const file of allFiles) {
                        const nameSimilarity = calculateSimilarity(fileName, file.name);
                        const pathSimilarity = calculateSimilarity(normalizedFilePath, file.path);
                        const combinedScore = (nameSimilarity * 0.7) + (pathSimilarity * 0.3);

                        if (combinedScore > bestScore) {
                            bestScore = combinedScore;
                            bestMatch = file;
                        }
                    }

                    if (bestMatch && bestScore > 0.5) { // Threshold for fuzzy match
                        foundFilePath = bestMatch.path;
                        console.log(`Fuzzy match found (score: ${bestScore.toFixed(2)}): ${foundFilePath}`);
                    }
                }
            }
        } catch (error) {
            console.log(`Error searching repository tree: ${error.response?.data || error.message}`);
            // Fallback to original path if search fails
            foundFilePath = normalizedFilePath;
        }

        // If no match found, use original path
        if (!foundFilePath) {
            console.log(`No match found, using original path: ${normalizedFilePath}`);
            foundFilePath = normalizedFilePath;
        }

        // Encode the file path for URL
        const encodedFilePath = foundFilePath.split('/').map(segment => encodeURIComponent(segment)).join('/');
        
        // Construct the GitLab blob URL
        let fileUrl = `${projectUrl}/-/blob/${encodeURIComponent(branch)}/${encodedFilePath}`;
        
        if (lineNumber) {
            fileUrl += `#L${lineNumber}`;
        }

        console.log(`Final file URL: ${fileUrl}`);
        return fileUrl;
    } catch (error) {
        console.log("Error constructing source file path:", error.message);
        return null;
    }
}

module.exports = {checkLabelExists, createLabels, createIssue, listExistingOpenIssues, createWikiPage, createComment, fetchAllPipelines, getPipelineVariables, cancelPipeline, updateCommitStatus, getSourceFilePath}