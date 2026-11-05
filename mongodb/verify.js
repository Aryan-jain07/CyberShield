/* eslint-disable no-console */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { MongoClient } = require('mongodb');
async function verify() {
  const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  const db = client.db();
  const collections = await db.listCollections().toArray();
  const expected = ['threat_indicators', 'threat_actors', 'threat_reports'];
  for (const name of expected) {
    if (!collections.some((collection) => collection.name === name)) throw new Error(`Missing MongoDB collection: ${name}`);
    console.log(`${name}: ${await db.collection(name).countDocuments()} documents`);
  }
  const demo = await db.collection('threat_indicators').findOne({ indicator: 'https://secure-login-check.example.test/verify' });
  if (!demo) throw new Error('Demo threat-intelligence indicator is missing.');
  console.log(`Demo indicator match: ${demo.indicator} (${demo.threat_actor})`);
  await client.close();
}
verify().catch((error) => { console.error(error); process.exitCode = 1; });
