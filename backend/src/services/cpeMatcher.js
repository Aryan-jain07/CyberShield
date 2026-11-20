function normalize(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function compareVersion(left, right) {
  const a = String(left || '').split(/[._-]/).map((part) => /^\d+$/.test(part) ? Number(part) : part);
  const b = String(right || '').split(/[._-]/).map((part) => /^\d+$/.test(part) ? Number(part) : part);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    if (a[index] === undefined) return -1;
    if (b[index] === undefined) return 1;
    if (a[index] === b[index]) continue;
    if (typeof a[index] === 'number' && typeof b[index] === 'number') return a[index] - b[index];
    return String(a[index]).localeCompare(String(b[index]));
  }
  return 0;
}

function versionMatches(version, range) {
  if (!range) return true;
  if (range.versionStartIncluding && compareVersion(version, range.versionStartIncluding) < 0) return false;
  if (range.versionStartExcluding && compareVersion(version, range.versionStartExcluding) <= 0) return false;
  if (range.versionEndIncluding && compareVersion(version, range.versionEndIncluding) > 0) return false;
  if (range.versionEndExcluding && compareVersion(version, range.versionEndExcluding) >= 0) return false;
  return true;
}

function matchSoftwareToProducts(software, products = []) {
  const vendor = normalize(software.vendor);
  const product = normalize(software.name);
  const candidates = products.filter((item) => normalize(item.vendor) === vendor && normalize(item.product) === product);
  if (!candidates.length) return { type: 'UNMATCHED', evidence: { reason: 'Vendor and product did not match any NVD CPE.', software: { vendor: software.vendor, product: software.name, version: software.version } } };
  const exact = candidates.some((item) => item.version !== '*' && normalize(item.version) === normalize(software.version) && versionMatches(software.version, item.versions?.[0]));
  if (exact) return { type: 'EXACT', evidence: { reason: 'Vendor, product, and version matched NVD CPE.', cpes: candidates } };
  const probable = candidates.some((item) => versionMatches(software.version, item.versions?.[0]));
  return probable
    ? { type: 'PROBABLE', evidence: { reason: 'Vendor and product matched and version range may apply; analyst verification required.', cpes: candidates } }
    : { type: 'UNMATCHED', evidence: { reason: 'Vendor and product matched but installed version was outside the affected range.', cpes: candidates } };
}

module.exports = { normalize, compareVersion, versionMatches, matchSoftwareToProducts };
