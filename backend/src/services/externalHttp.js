const { setTimeout: delay } = require('node:timers/promises');

async function requestJson(url, { headers = {}, timeoutMs = 30_000, retries = 3, minDelayMs = 0, fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('Fetch is not available in this Node.js runtime.');
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (minDelayMs && attempt) await delay(minDelayMs);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { headers, signal: controller.signal });
      if (response.status === 429 || response.status >= 500) {
        const retryAfter = Number(response.headers?.get?.('retry-after')) || Math.min(60, 2 ** attempt);
        if (attempt < retries) { await delay(retryAfter * 1000); continue; }
      }
      if (!response.ok) throw new Error(`External request failed with HTTP ${response.status}.`);
      const body = await response.json();
      if (!body || typeof body !== 'object') throw new Error('External response was not a JSON object.');
      return body;
    } catch (error) {
      lastError = error.name === 'AbortError' ? new Error(`External request timed out after ${timeoutMs}ms.`) : error;
      if (attempt < retries) await delay(Math.min(60_000, 2 ** attempt * 1000));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError || new Error('External request failed.');
}

module.exports = { requestJson };
