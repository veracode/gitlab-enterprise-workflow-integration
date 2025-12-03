const SCAN = {
    'PIPELINE_SCAN' : "PipelineScan",
    'POLICY_SCAN' : "PolicyScan",
    'SCA_SCAN' : "ScaScan",
    'ICA_SCAN' : "IacScan"
};

const STATUS = {
    'Findings' : 'Findings',
    'Success' : 'Success',
    'Error' : 'Error'
};

const SCAN_RESPONSE_CODE = {
    'POLICY_EVALUATION_FAILED' : 'POLICY_EVALUATION_FAILED',
    'SCAN_TIME_OUT' : 'SCAN_TIME_OUT',
    'FINISHED' : 'FINISHED',
    'IN_PROGRESS' : 'IN_PROGRESS'
}

const PLATFORM_SCAN_STATUS = {
    'MODULE_SELECTION_REQUIRED' : 'MODULE_SELECTION_REQUIRED',
    'PRE_SCAN_SUCCESS' : 'PRE-SCAN_SUCCESS',
    'PUBLISHED' : 'PUBLISHED',
    'RESULTS_READY' : 'RESULTS_READY',
    'SCAN_IN_PROGRESS' : 'SCAN_IN_PROGRESS'
}


module.exports = {
    SCAN,
    STATUS,
    SCAN_RESPONSE_CODE,
    PLATFORM_SCAN_STATUS
}