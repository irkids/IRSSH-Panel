const autocannon = require('autocannon');
const { promisify } = require('util');
const { writeFileSync } = require('fs');

const run = promisify(autocannon);

const URL = 'http://localhost:3000/api/v1';
const TOKEN = 'your-test-token';

async function runProtocolTest() {
  const result = await run({
    url: `${URL}/protocols`,
    connections: 100,
    duration: 30,
    headers: {
      'Authorization': `Bearer ${TOKEN}`
    },
    requests: [
      {
        method: 'GET',
        path: '/protocols'
      },
      {
        method: 'GET',
        path: '/protocols/metrics'
      }
    ]
  });

  writeFileSync('protocol-performance.json', JSON.stringify(result, null, 2));
  console.log(result);
}

async function runCreateProtocolTest() {
  const result = await run({
    url: `${URL}/protocols`,
    connections: 50,
    duration: 20,
    headers: {
      'Authorization': `Bearer ${TOKEN}`,
      'Content-Type': 'application/json'
    },
    requests: [
      {
        method: 'POST',
        path: '/protocols',
        body: JSON.stringify({
          name: 'Test Protocol',
          type: 'SSH',
          config: {
            port: 22,
            maxConnections: 100
          }
        })
      }
    ]
  });

  writeFileSync('protocol-create-performance.json', JSON.stringify(result, null, 2));
  console.log(result);
}

runProtocolTest().catch(console.error);
runCreateProtocolTest().catch(console.error);
