const rules = [
  { category: 'Phishing', severity: 'HIGH', keywords: ['phishing', 'suspicious email', 'malicious link', 'credential', 'login url'], techniques: ['T1566', 'T1204'] },
  { category: 'Credential Access', severity: 'HIGH', keywords: ['credential stuffing', 'brute force', 'password spray', 'authentication attempts'], techniques: ['T1110', 'T1078'] },
  { category: 'Malware Execution', severity: 'HIGH', keywords: ['powershell', 'malware', 'encoded command', 'payload'], techniques: ['T1059.001', 'T1027'] },
  { category: 'Command and Control', severity: 'CRITICAL', keywords: ['beacon', 'command and control', 'c2', 'periodic connection'], techniques: ['T1071.001'] },
  { category: 'Ransomware', severity: 'CRITICAL', keywords: ['ransomware', 'encrypted files', 'ransom note'], techniques: ['T1486'] }
];

function unique(values) { return [...new Set(values)]; }

function analyzeIncidentText(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  const matches = rules.filter((rule) => rule.keywords.some((keyword) => text.includes(keyword)));
  const indicators = unique([
    ...(text.match(/https?:\/\/[^\s"')]+/g) || []),
    ...(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []),
    ...(text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || [])
  ]);
  const keywords = unique(matches.flatMap((rule) => rule.keywords.filter((keyword) => text.includes(keyword))));
  return {
    suggested_category: matches[0]?.category || 'General Security Event',
    suggested_severity: matches.some((rule) => rule.severity === 'CRITICAL') ? 'CRITICAL' : matches[0]?.severity || 'MEDIUM',
    suggested_techniques: unique(matches.flatMap((rule) => rule.techniques)),
    extracted_keywords: keywords,
    extracted_indicators: indicators,
    confidence_note: 'Rule-based analyst assistance only. Suggestions require analyst confirmation.'
  };
}

module.exports = { analyzeIncidentText };
