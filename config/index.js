function veracodeConfig() {
  return {
    applicationUri: '/appsec/v1/applications',
    findingsUri: '/appsec/v2/applications',
    hostName: {
      'US': 'api.veracode.com',
      'EU': 'api.veracode.eu'
    },
    policyUri: '/appsec/v1/policies',
    teamsUri: '/api/authn/v2/teams',
    selfUserUri: '/api/authn/v2/users/self',
    pollingInterval: 30000,
    moduleSelectionTimeout: 60000,
    scanStatusApiTimeout: 600000, // 10 minutes
    defaultPolicyUuid: '9ab6dc63-29cf-4457-a1d1-e2125277df0e',
    sandboxScanName: 'Gitlab extension scans - ',
    sandboxUri: '/appsec/v1/applications/${appGuid}/sandboxes',
    cliLatestVersionUrl: 'https://tools.veracode.com/veracode-cli/LATEST_VERSION',
    cliDownloadUrl: 'https://tools.veracode.com/veracode-cli/',
  }
}

function appConfig() {
  return {
    pushEventName: "Push Hook",
    pullRequestEventName: "Merge Request Hook",
    logPrefix: `[veracode]: `,
    policyScanResult: "policy_scan_results.json",
    pipelineScanFile: "pipeline.json",
    filteredScanFile: "filtered_results.json",
    scaScanFileName: "sca_results.json",
    iacScanFileName: "results.json",
  };
}

module.exports = {
  veracodeConfig,
  appConfig
}