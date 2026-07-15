const axios = require('axios');

// Vulnerable to CVE-2023-45857 (SSRF via credential leakage on cross-origin redirect)
// axios <1.6.0 forwarded Authorization header on cross-origin redirects.
async function fetchProduct(id) {
  const res = await axios.get(`https://api.example.com/products/${id}`, {
    headers: { Authorization: 'Bearer secret-token' },
  });
  return res.data;
}

module.exports = { fetchProduct };
