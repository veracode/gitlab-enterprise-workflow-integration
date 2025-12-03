const VERACODE_FLAW_LABELS = {
    "Very High": {
        'name': 'VeracodeFlaw: Very High',
        'color': '#A90533',
        'description': 'A Veracode Flaw, Very High severity',
    },
    High: {
        'name': 'VeracodeFlaw: High',
        'color': '#DD3B35',
        'description': 'A Veracode Flaw, High severity'
    },
    Medium: {
        'name': 'VeracodeFlaw: Medium',
        'color': '#FF7D00',
        'description': 'A Veracode Flaw, Medium severity'
    },
    Low: {
        'name': 'VeracodeFlaw: Low',
        'color': '#FFBE00',
        'description': 'A Veracode Flaw, Low severity'
    },
    "Very Low":{
        'name': 'VeracodeFlaw: Very Low',
        'color': '#33ADD2',
        'description': 'A Veracode Flaw, Very Low severity',
    },
    Informational: {
        'name': 'VeracodeFlaw: Informational',
        'color': '#0270D3',
        'description': 'A Veracode Flaw, Informational severity',
    },
    Unknown: {
        'name': 'VeracodeFlaw: Unknown',
        'color': '#0270D3',
        'description': 'A Veracode Flaw,Unknown severity',
    }
};

const VERACODE_SCA_LABEL = {
    'name': 'Veracode SCA Scan',
    'color': '#0AA2DC',
    'description': 'A Veracode identified vulnerability during a SCA Scan'
};

const VERACODE_STATIC_LABELS = [{
    'name': 'Veracode Pipeline Scan',
    'color': '#76a6b6',
    'description': 'A Veracode Flaw found during a Pipeline Scan'
},{
    'name': 'Veracode Policy Scan',
    'color': '#666698',
    'description': 'A Veracode Flaw found during a Policy or Sandbox Scan'
}];

module.exports = { VERACODE_FLAW_LABELS, VERACODE_SCA_LABEL, VERACODE_STATIC_LABELS };