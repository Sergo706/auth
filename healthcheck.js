import http from 'node:http';



const options = {
  host: '127.0.0.1',
  port: 10000,
  path: '/health',
  timeout: 2000,
};



const request = http.request(options, (res) => {
  if (res.statusCode >= 200 && res.statusCode < 300 || res.statusCode === 401) {
    process.exit(0);
  } else {
    console.error(`Unhealthy Status: ${res.statusCode}`);
    process.exit(1);
  }
});

request.on('error', (err) => {
  console.error('Connection Error:', err.message);
  process.exit(1);
});


request.end();