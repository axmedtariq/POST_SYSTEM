const sql = require('mssql'); 
// ...
const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_HOST, // Your server name/instance
  database: process.env.DB_NAME, // POST_APPLICATION
  options: {
    // ...
    trustServerCertificate: true // Crucial for local development
  }
};