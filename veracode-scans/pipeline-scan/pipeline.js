const fs = require('fs');
const path = require('path');
const { SCAN, STATUS } = require('../../config/constants');
const { appConfig } = require('../../config');
const { exitOnFailure, updateErrorMessage, uploadArtifact } = require('../../utility/utils');
const execa = require('execa');
const { getApplicationByName, getApplicationFindings, isProfileExists, veracodePolicyVerification, validateCredential } = require('../../utility/common');
const pipelineScanIssue = require('../../veracode-issues/pipelineScanIssue');
const displayScanResult = require('../../displayScanResult');
const { execSync } = require('child_process');

async function pipelineScan(apiId, apiKey, appProfileName, filterMitigatedFlaws, breakBuildOnFinding, breakBuildOnError, userErrorMessage, policyName, breakBuildOnInvalidPolicy, createIssue) {
    const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');

    try {
        const isCredentialValid = await validateCredential(apiId, apiKey);

        if (!isCredentialValid) {
            await displayScanResult([], "Veracode credentials are invalid or expired.");
            exitOnFailure(breakBuildOnError);
            return;
        }

        const invalidPolicy = await veracodePolicyVerification(apiId, apiKey, policyName, breakBuildOnInvalidPolicy);
        if (invalidPolicy) {
            await displayScanResult([], "Invalid Veracode Policy name.");
            exitOnFailure(breakBuildOnInvalidPolicy);
        }

        const artifacts = await fs.promises.readdir(veracodeArtifactsDir);
        const scanResults = await Promise.all(
            artifacts.map((artifact) =>
                executePipelineScan(veracodeArtifactsDir, artifact, apiId, apiKey)
            )
        );

        if (!scanResults) {
            console.log(`No artifact file found in the ${veracodeArtifactsDir} directory.`);
        }

        const failedScans = scanResults.filter((result) => !result.success);
        const uniqueCombinations = new Set();
        let filteredResult = { findings: [] };

        for (const failedScan of failedScans) {
            const artifactName = failedScan.artifact.replace(/\.[^/.]+$/, '');
            const simplifiedFileName = (resultFileName) =>
                resultFileName.includes('pipeline') ? 'pipeline.json' : 'filtered_results.json';

            // Loop through each result file in the failed scan
            for (const resultFileName of failedScan.results) {
                try {
                    // Check if the result file exists
                    if (!fs.existsSync(resultFileName)) {
                        console.log(`${resultFileName} is not present... Continuing`);
                        continue; // Skip if file doesn't exist
                    }

                    // Read and parse the result file
                    let rawData = fs.readFileSync(resultFileName);
                    let resultsJSON = JSON.parse(rawData.toString());

                    // Awaiting async operations for upload and flaw mitigation
                    await uploadArtifact(veracodeArtifactsDir, artifactName, simplifiedFileName(resultFileName), JSON.stringify(resultsJSON, null, 2));
                    const isFilterMitigatedFlaws = filterMitigatedFlaws === 'true' ? true : filterMitigatedFlaws === 'false' ? false : filterMitigatedFlaws;
                    let mitigatedResult = resultsJSON;
                    if (isFilterMitigatedFlaws) {
                        mitigatedResult = await mitigatedFlaws(apiId, apiKey, appProfileName, resultsJSON, veracodeArtifactsDir, artifactName);
                    }
                    // Filter findings
                    let filteredFindings = mitigatedResult.findings.filter((finding) => {
                        const key = `${finding.cwe_id}-${finding.files.source_file.line}-${finding.files.source_file.file}`;
                        if (uniqueCombinations.has(key)) {
                            return false;
                        } else {
                            uniqueCombinations.add(key);
                            return true;
                        }
                    });

                    // Update the filtered results
                    filteredResult.findings = [
                        ...filteredResult.findings,
                        ...filteredFindings,
                    ];
                } catch (error) {
                    console.error(`Error processing the file ${resultFileName}:`, error);
                }
            }
        }

        const pipelineScanFile = appConfig().pipelineScanFile;
        let pipelineResult = {
            scan: SCAN.PIPELINE_SCAN,
            fileName: pipelineScanFile,
        };

        if (filteredResult.findings.length > 0) {
            await displayScanResult(filteredResult.findings);

            if (createIssue) {
                await pipelineScanIssue(filteredResult);
            }

            pipelineResult.result = JSON.stringify(filteredResult, null, 2);
            pipelineResult.status = STATUS.Findings;
            pipelineResult.message = 'Vulnerability detected in the repository';
            exitOnFailure(breakBuildOnFinding);

            return pipelineResult;
        } else {
            await displayScanResult([]);
            console.log('No pipeline findings, exiting and updating the GitLab check status to success');
            pipelineResult.message = 'No pipeline findings.';
            pipelineResult.status = STATUS.Success;
            return pipelineResult;
        }
    } catch (error) {
        error = updateErrorMessage(breakBuildOnError, userErrorMessage, error);
        console.error(`Error while processing pipeline scan execution : ${error}`);
        exitOnFailure(breakBuildOnError);
    }
}

async function executePipelineScan(veracodeArtifactsDir, artifactName, apiId, apiKey) {
    const pipelineResultFileName = `${artifactName}-` + appConfig().pipelineScanFile;
    const filteredResultFileName = `${artifactName}-` + appConfig().filteredScanFile;

    try {
        const artifactFilePath = path.join(veracodeArtifactsDir, artifactName);
        const pipelineScanJarPath = path.join(__dirname, 'pipeline-scan.jar');
        const pipelineScanCommand = `java -jar ${pipelineScanJarPath} -vid ${apiId} -vkey ${apiKey} -f ${artifactFilePath} -jf ${pipelineResultFileName} -fjf ${filteredResultFileName}`;

        execSync(pipelineScanCommand, { stdio: 'inherit' });
        return { artifact: artifactName, success: true, results: [] };
    } catch (error) {
        const errorMessage = `${appConfig().logPrefix} Vulnerability detected in the repository for ${artifactName}`;
        return { artifact: artifactName, success: false, error: errorMessage, results: [pipelineResultFileName, filteredResultFileName] };
    }
}

async function mitigatedFlaws(apiId, apiKey, appProfileName, results, veracodeArtifactsDir, artifactName) {
    let policyFindings = [];
    const LINE_NUMBER_SLOP = 3;
    try {
        const responseData = await getApplicationByName(apiId, apiKey, appProfileName);
        const appDetail = isProfileExists(responseData, appProfileName);
        const applicationGuid = appDetail?.veracodeApp?.appGuid;
        policyFindings = await getApplicationFindings(applicationGuid, apiId, apiKey);
    } catch (error) {
        console.log(`No application found with name ${appProfileName}`);
        policyFindings = [];
    }

    let policyFindingsToExclude = [];
    policyFindingsToExclude = policyFindings.filter((finding) => {
        return (
            finding.violates_policy === true &&
            finding.finding_status.status === 'CLOSED' &&
            (finding.finding_status.resolution === 'POTENTIAL_FALSE_POSITIVE' ||
                finding.finding_status.resolution === 'MITIGATED') &&
            finding.finding_status.resolution_status === 'APPROVED'
        );
    });

    if (policyFindingsToExclude.length > 0) {
        // Remove item in results if there are items in policyFindingsToExclude if the file_path and
        // cwe_id and line_number are the same
        const defaultResultLength = results.findings.length;
        let filteredFindingsArray = results.findings.filter((finding) => {
            return !policyFindingsToExclude.some((mitigatedFinding) => {
                if (mitigatedFinding.finding_details.file_path.charAt(0) === '/') {
                    mitigatedFinding.finding_details.file_path = mitigatedFinding.finding_details.file_path.substring(1);
                }

                return (
                    finding.files.source_file.file === mitigatedFinding.finding_details.file_path &&
                    +finding.cwe_id === mitigatedFinding.finding_details.cwe.id &&
                    Math.abs(finding.files.source_file.line - mitigatedFinding.finding_details.file_line_number) <= LINE_NUMBER_SLOP
                );
            });
        });

        results.findings = filteredFindingsArray;

        if (filteredFindingsArray.length !== defaultResultLength) {
            uploadArtifact(veracodeArtifactsDir, artifactName, 'mitigated_result.json', JSON.stringify(results, null, 2));
        }
    }
    return results;
}

module.exports = pipelineScan;
