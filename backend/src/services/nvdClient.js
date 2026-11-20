const { nvdApiKey } = require('../config');
const { requestJson } = require('./externalHttp');

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

function firstEnglish(items = []) {
  return items.find((item) => item.lang === 'en')?.value || items[0]?.value || '';
}

function metricValue(metric) {
  const data = metric?.cvssData || metric;
  return data && {
    version: data.version,
    vectorString: data.vectorString,
    baseScore: data.baseScore,
    baseSeverity: data.baseSeverity,
    attackVector: data.attackVector,
    attackComplexity: data.attackComplexity,
    privilegesRequired: data.privilegesRequired,
    userInteraction: data.userInteraction
  };
}

function cpeProduct(criteria, versions) {
  const parts = String(criteria || '').split(':');
  return {
    cpe: criteria,
    vendor: parts[3] || null,
    product: parts[4] || null,
    version: parts[5] || null,
    versions: versions || []
  };
}

function collectCpes(configurations = [], result = []) {
  for (const configuration of configurations) {
    for (const node of configuration.nodes || []) {
      for (const match of node.cpeMatch || []) {
        if (match.vulnerable !== false) result.push(cpeProduct(match.criteria, [{
          versionStartIncluding: match.versionStartIncluding || null,
          versionStartExcluding: match.versionStartExcluding || null,
          versionEndIncluding: match.versionEndIncluding || null,
          versionEndExcluding: match.versionEndExcluding || null
        }]));
      }
      collectCpes(node.children ? [{ nodes: node.children }] : [], result);
    }
  }
  return result;
}

function normalizeNvdCve(item) {
  const cve = item?.cve;
  if (!cve?.id || !/^CVE-\d{4}-\d{4,}$/i.test(cve.id)) throw new Error('NVD record is missing a valid CVE ID.');
  const metrics = {};
  for (const key of ['cvssMetricV40', 'cvssMetricV4', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    if (cve.metrics?.[key]?.[0]) metrics[key] = metricValue(cve.metrics[key][0]);
  }
  const preferred = metrics.cvssMetricV40 || metrics.cvssMetricV4 || metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || {};
  return {
    cveId: cve.id.toUpperCase(),
    description: firstEnglish(cve.descriptions),
    publishedAt: cve.published || null,
    lastModifiedAt: cve.lastModified || null,
    externalStatus: cve.vulnStatus || null,
    metrics,
    cvssScore: preferred.baseScore ?? null,
    severity: preferred.baseSeverity || null,
    attackVector: preferred.attackVector || null,
    attackComplexity: preferred.attackComplexity || null,
    privilegesRequired: preferred.privilegesRequired || null,
    userInteraction: preferred.userInteraction || null,
    cweIds: [...new Set((cve.weaknesses || []).flatMap((weakness) => (weakness.description || []).map((item) => item.value).filter((value) => /^CWE-/i.test(value))))],
    affectedProducts: collectCpes(cve.configurations),
    referenceUrls: (cve.references || []).map((reference) => ({ url: reference.url, source: reference.source || null, tags: reference.tags || [] })).filter((reference) => reference.url)
  };
}

async function *fetchNvd({ modifiedSince = null, startIndex = 0, now = new Date(), pageSize = 2000, onPage, fetchImpl } = {}) {
  const endDate = now.toISOString();
  while (true) {
    const params = new URLSearchParams({ startIndex: String(startIndex), resultsPerPage: String(pageSize) });
    if (modifiedSince) {
      params.set('lastModStartDate', new Date(modifiedSince).toISOString());
      params.set('lastModEndDate', endDate);
    }
    const body = await requestJson(`${NVD_URL}?${params}`, {
      headers: nvdApiKey ? { apiKey: nvdApiKey } : {},
      minDelayMs: nvdApiKey ? 100 : 6_000,
      fetchImpl
    });
    if (!Array.isArray(body.vulnerabilities)) throw new Error('NVD response did not contain a vulnerabilities array.');
    const normalized = body.vulnerabilities.map(normalizeNvdCve);
    for (const item of normalized) yield item;
    startIndex += normalized.length;
    if (onPage) await onPage({ nextStartIndex: startIndex, count: normalized.length, maxModifiedAt: normalized.reduce((max, item) => item.lastModifiedAt && (!max || new Date(item.lastModifiedAt) > new Date(max)) ? item.lastModifiedAt : max, modifiedSince) });
    if (!body.vulnerabilities.length || startIndex >= Number(body.totalResults || 0)) break;
  }
}

module.exports = { NVD_URL, normalizeNvdCve, fetchNvd };
