const response = await fetch('http://192.168.4.1/api/apply', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: 'func=config&ssid=NAKIB&password=69697833'
});

const result = await response.json();
console.log(result);