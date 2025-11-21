require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const sql = require('mssql');

const app = express();
const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = process.env.JWT_EXPIRY || '1h';

// ===== Database Connection (SQL Server) =====
const dbConfig = {
  server: process.env.DB_HOST.trim(),
  user: process.env.DB_USER.trim(),
  password: process.env.DB_PASS.trim(),
  database: process.env.DB_NAME.trim(),
  port: parseInt(process.env.DB_PORT.trim(), 10),
  options: {
    trustServerCertificate: true,
    encrypt: false,
  },
  port: 1435
};

// ✅ Check database connection
sql.connect(dbConfig)
  .then(() => console.log('✅ MSSQL Database connected successfully'))
  .catch(err => console.error('❌ MSSQL Database connection failed:', err.message));

// ===== Middleware =====
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'frontend')));

// ===== Auth Middleware =====
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'token Error' });
  }
};

// ===== Authentication Routes =====
// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role)
      return res.status(400).json({ error: 'Missing fields' });

    const hash = await bcrypt.hash(password, 10);
    const request = new sql.Request();
    await request.query`
      INSERT INTO users (email, password_hash, role)
      VALUES (${email}, ${hash}, ${role})
    `;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const request = new sql.Request();
    const result = await request.query`SELECT * FROM users WHERE email=${email}`;
    if (result.recordset.length === 0)
      return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.recordset[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Products CRUD =====
app.get('/api/products', authMiddleware, async (req, res) => {
  try {
    const request = new sql.Request();
    const result = await request.query`SELECT * FROM products ORDER BY id`;
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/products', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const { name, price, stock } = req.body;
    const request = new sql.Request();
    await request.query`
      INSERT INTO products (name, price, stock)
      VALUES (${name}, ${price}, ${stock})
    `;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/products/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const { id } = req.params;
    const { name, price, stock } = req.body;
    const request = new sql.Request();
    await request.query`
      UPDATE products SET name=${name}, price=${price}, stock=${stock} WHERE id=${id}
    `;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/products/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const { id } = req.params;
    const request = new sql.Request();
    await request.query`DELETE FROM products WHERE id=${id}`;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Checkout =====
app.post('/api/checkout', authMiddleware, async (req, res) => {
  const { items, customer } = req.body;
  if (!items || !items.length) return res.status(400).json({ error: 'Cart empty' });
  if (!customer || !customer.name || !customer.address || !customer.phone)
    return res.status(400).json({ error: 'Customer information required' });

  const transaction = new sql.Transaction();
  try {
    await transaction.begin();
    const request = new sql.Request(transaction);
    let total = 0;

    for (const item of items) {
      const prodRes = await request.query`
        SELECT stock, price FROM products WHERE id=${item.product_id}
      `;
      if (prodRes.recordset.length === 0)
        throw new Error(`Product ${item.product_id} not found`);

      const prod = prodRes.recordset[0];
      if (prod.stock < item.qty)
        throw new Error(`Not enough stock for product ${item.product_id}`);

      const dbPrice = Number(prod.price);
      total += dbPrice * Number(item.qty);

      await request.query`
        UPDATE products SET stock = stock - ${item.qty} WHERE id = ${item.product_id}
      `;
      item.price = dbPrice;
    }

    const saleInsert = await request.query`
      INSERT INTO sales (total, customer_name, customer_address, customer_phone, created_at)
      OUTPUT INSERTED.id AS id
      VALUES (${total}, ${customer.name}, ${customer.address}, ${customer.phone}, GETDATE())
    `;
    const saleId = saleInsert.recordset[0].id;

    for (const item of items) {
      await request.query`
        INSERT INTO sale_items (sale_id, product_id, qty, price)
        VALUES (${saleId}, ${item.product_id}, ${item.qty}, ${item.price})
      `;
    }

    await transaction.commit();
    res.json({ ok: true, sale_id: saleId });
  } catch (err) {
    await transaction.rollback();
    res.status(400).json({ error: err.message });
  }
});

// ===== Sales Reports =====
app.get('/api/sales', authMiddleware, async (req, res) => {
  try {
    const request = new sql.Request();
    const salesRes = await request.query`SELECT TOP 5 * FROM sales ORDER BY created_at DESC`;
    const sales = salesRes.recordset;
    if (sales.length === 0) return res.json([]);

    const saleIds = sales.map(s => s.id).join(',');
    const itemsRes = await request.query(`
      SELECT si.sale_id, si.product_id, si.qty, si.price, p.name
      FROM sale_items si
      JOIN products p ON p.id = si.product_id
      WHERE si.sale_id IN (${saleIds})
    `);

    const itemsBySale = {};
    for (const row of itemsRes.recordset) {
      if (!itemsBySale[row.sale_id]) itemsBySale[row.sale_id] = [];
      itemsBySale[row.sale_id].push({
        product_id: row.product_id,
        name: row.name,
        qty: row.qty,
        price: row.price,
      });
    }

    const withItems = sales.map(s => ({
      ...s,
      items: itemsBySale[s.id] || [],
    }));

    res.json(withItems);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Start Server =====
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
