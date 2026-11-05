/* eslint-disable no-console */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { MongoClient } = require('mongodb');

const uri = process.env.MONGODB_URI;
if (!uri) throw new Error('MONGODB_URI must be set in .env.');

const threatIndicators = [
  {
    indicator: 'https://secure-login-check.example.test/verify', type: 'URL', malicious: true,
    confidence: 96, threat_actor: 'Example Group', techniques: ['T1566', 'T1204'],
    tags: ['phishing', 'credential-harvesting'], source: 'Synthetic Threat Intelligence', first_seen: new Date('2026-09-01')
  },
  {
    indicator: '185.23.45.10', type: 'IP', malicious: true, confidence: 92,
    threat_actor: 'Synthetic Group 2', techniques: ['T1071.001'], tags: ['command-and-control'],
    source: 'Synthetic Threat Intelligence', first_seen: new Date('2026-08-15')
  },
  {
    indicator: 'credential-portal.example.test', type: 'DOMAIN', malicious: true, confidence: 89,
    threat_actor: 'Example Group', techniques: ['T1566'], tags: ['phishing'],
    source: 'Synthetic Threat Intelligence', first_seen: new Date('2026-09-03')
  }
];

const threatActors = [
  { name: 'Example Group', aliases: ['EG'], motivation: 'Credential theft', confidence: 95, techniques: ['T1566', 'T1204'], source: 'Synthetic Threat Intelligence' },
  { name: 'Synthetic Group 2', aliases: ['SG2'], motivation: 'Access brokerage', confidence: 82, techniques: ['T1071.001', 'T1110'], source: 'Synthetic Threat Intelligence' }
];

const threatReports = [{
  report_id: 'SYN-2026-001', title: 'Credential Harvesting Campaign', published_at: new Date('2026-09-10'),
  severity: 'HIGH', indicators: threatIndicators.slice(0, 2).map(({ indicator }) => indicator),
  techniques: ['T1566', 'T1204'], source: 'Synthetic Threat Intelligence', summary: 'Synthetic report for CyberShield correlation testing.'
}];

async function seed() {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  const db = client.db();
  await db.collection('threat_indicators').deleteMany({ source: 'Synthetic Threat Intelligence' });
  await db.collection('threat_actors').deleteMany({ source: 'Synthetic Threat Intelligence' });
  await db.collection('threat_reports').deleteMany({ source: 'Synthetic Threat Intelligence' });
  await db.collection('threat_indicators').insertMany(threatIndicators);
  await db.collection('threat_actors').insertMany(threatActors);
  await db.collection('threat_reports').insertMany(threatReports);
  await db.collection('threat_indicators').createIndex({ indicator: 1 }, { unique: true });
  await db.collection('threat_indicators').createIndex({ type: 1, malicious: 1 });
  await db.collection('threat_actors').createIndex({ name: 1 }, { unique: true });
  await db.collection('threat_reports').createIndex({ report_id: 1 }, { unique: true });
  console.table(await db.collection('threat_indicators').aggregate([{ $group: { _id: '$type', count: { $sum: 1 } } }]).toArray());
  await client.close();
}
seed().catch((error) => { console.error(error); process.exitCode = 1; });
