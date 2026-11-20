const { requestJson } = require('./externalHttp');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

function normalizeKevCatalog(body) {
  if (!body || !Array.isArray(body.vulnerabilities)) throw new Error('CISA KEV response did not contain a vulnerabilities array.');
  return {
    version: body.catalogVersion || null,
    releasedAt: body.dateReleased || null,
    vulnerabilities: body.vulnerabilities.map((item) => {
      if (!item.cveID || !/^CVE-\d{4}-\d{4,}$/i.test(item.cveID)) throw new Error('CISA KEV record is missing a valid CVE ID.');
      return {
        cveId: item.cveID.toUpperCase(),
        vendorProject: item.vendorProject || null,
        product: item.product || null,
        vulnerabilityName: item.vulnerabilityName || null,
        dateAdded: item.dateAdded || null,
        shortDescription: item.shortDescription || null,
        requiredAction: item.requiredAction || null,
        dueDate: item.dueDate || null,
        knownRansomwareCampaignUse: item.knownRansomwareCampaignUse || null,
        cweIds: Array.isArray(item.cwes) ? item.cwes : []
      };
    })
  };
}

async function fetchKev({ fetchImpl } = {}) {
  return normalizeKevCatalog(await requestJson(KEV_URL, { fetchImpl, minDelayMs: 0 }));
}

module.exports = { KEV_URL, normalizeKevCatalog, fetchKev };
