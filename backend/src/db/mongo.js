const { MongoClient } = require('mongodb');
const { mongoUri } = require('../config');

const client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000 });
let database;

async function getMongoDb() {
  if (!database) {
    await client.connect();
    database = client.db();
  }
  return database;
}

async function closeMongo() { await client.close(); }
module.exports = { getMongoDb, closeMongo };
