const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();

app.use(express.json({ limit: "1mb" }));

/*
  CORS
  Development mein "*" allowed hai.
  Production mein FRONTEND_ORIGIN environment variable
  set karne par sirf wahi frontend allowed hoga.
*/
const frontendOrigin = process.env.FRONTEND_ORIGIN || "*";

app.use(
  cors({
    origin: frontendOrigin,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

/* =========================
   CONFIG
========================= */

const PORT = Number(process.env.PORT) || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET environment variable is missing.");
  process.exit(1);
}

/* =========================
   DATABASE
========================= */

const db = new Database("dukaan.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  shop_name TEXT NOT NULL,
  mobile TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  language TEXT DEFAULT 'Hindi',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS purchase_lots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  product TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  remaining_quantity INTEGER NOT NULL,
  cost_paise INTEGER NOT NULL,
  purchase_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  product TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  selling_price_paise INTEGER NOT NULL,
  revenue_paise INTEGER NOT NULL,
  cogs_paise INTEGER NOT NULL,
  gross_profit_paise INTEGER NOT NULL,
  sale_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sale_fifo_layers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_id INTEGER NOT NULL,
  purchase_lot_id INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  cost_paise INTEGER NOT NULL,

  FOREIGN KEY(sale_id) REFERENCES sales(id) ON DELETE CASCADE,
  FOREIGN KEY(purchase_lot_id) REFERENCES purchase_lots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  description TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  expense_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS khata (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  customer_name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('credit', 'payment')),
  amount_paise INTEGER NOT NULL,
  note TEXT DEFAULT '',
  entry_date TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_purchase_user_product
ON purchase_lots(user_id, product);

CREATE INDEX IF NOT EXISTS idx_sales_user_date
ON sales(user_id, sale_date);

CREATE INDEX IF NOT EXISTS idx_expenses_user_date
ON expenses(user_id, expense_date);

CREATE INDEX IF NOT EXISTS idx_khata_user_customer
ON khata(user_id, customer_name);
`);

/* =========================
   HELPERS
========================= */

function today() {
  return new Date().toISOString().slice(0, 10);
}

function validDate(value) {
  if (!value) return today();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("Date must be YYYY-MM-DD");
  }

  const d = new Date(value + "T00:00:00Z");

  if (Number.isNaN(d.getTime())) {
    throw new Error("Invalid date");
  }

  return value;
}

function normalizeProduct(product) {
  return String(product || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function cleanProduct(product) {
  const p = normalizeProduct(product);

  if (!p) {
    throw new Error("Product name is required");
  }

  return p;
}

function positiveInteger(value, field) {
  const n = Number(value);

  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`${field} must be a positive integer`);
  }

  return n;
}

function nonNegativeInteger(value, field) {
  const n = Number(value);

  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`${field} must be a non-negative integer`);
  }

  return n;
}

function moneyToPaise(value, field = "amount") {
  const n = Number(value);

  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`${field} must be a valid non-negative amount`);
  }

  return Math.round(n * 100);
}

function paiseToRupees(paise) {
  return Number((Number(paise || 0) / 100).toFixed(2));
}

function formatMoney(paise) {
  return `₹${paiseToRupees(paise).toFixed(2)}`;
}

function monthRange(year, month) {
  const y = Number(year);
  const m = Number(month);

  if (!Number.isInteger(y) || !Number.isInteger(m) || m < 1 || m > 12) {
    throw new Error("Invalid year or month");
  }

  const start = `${y}-${String(m).padStart(2, "0")}-01`;

  const nextYear = m === 12 ? y + 1 : y;
  const nextMonth = m === 12 ? 1 : m + 1;

  const end = `${nextYear}-${String(nextMonth).padStart(2, "0")}-01`;

  return { start, end };
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = db
      .prepare(
        `SELECT id, name, shop_name, mobile, language, created_at
         FROM users
         WHERE id = ?`
      )
      .get(decoded.userId);

    if (!user) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired login session"
    });
  }
}

function makeToken(userId) {
  return jwt.sign(
    {
      userId
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function userExists(userId) {
  return db
    .prepare(`SELECT id FROM users WHERE id = ?`)
    .get(userId);
}

/* =========================
   HEALTH CHECK
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    app: "Dukaan Manager Backend",
    status: "online"
  });
});

/* =========================
   AUTH
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      shopName,
      mobile,
      password,
      confirmPassword
    } = req.body;

    if (!name || !shopName || !mobile || !password) {
      return res.status(400).json({
        error: "Name, shop name, mobile and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters"
      });
    }

    if (confirmPassword !== undefined && password !== confirmPassword) {
      return res.status(400).json({
        error: "Passwords do not match"
      });
    }

    const existing = db
      .prepare(`SELECT id FROM users WHERE mobile = ?`)
      .get(String(mobile).trim());

    if (existing) {
      return res.status(409).json({
        error: "This mobile number is already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db
      .prepare(
        `INSERT INTO users
        (name, shop_name, mobile, password_hash)
        VALUES (?, ?, ?, ?)`
      )
      .run(
        String(name).trim(),
        String(shopName).trim(),
        String(mobile).trim(),
        passwordHash
      );

    const userId = Number(result.lastInsertRowid);

    const token = makeToken(userId);

    const user = db
      .prepare(
        `SELECT id, name, shop_name, mobile, language, created_at
         FROM users
         WHERE id = ?`
      )
      .get(userId);

    res.status(201).json({
      success: true,
      token,
      user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { mobile, password } = req.body;

    if (!mobile || !password) {
      return res.status(400).json({
        error: "Mobile and password are required"
      });
    }

    const user = db
      .prepare(
        `SELECT *
         FROM users
         WHERE mobile = ?`
      )
      .get(String(mobile).trim());

    if (!user) {
      return res.status(401).json({
        error: "Invalid mobile number or password"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid mobile number or password"
      });
    }

    const token = makeToken(user.id);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        shop_name: user.shop_name,
        mobile: user.mobile,
        language: user.language,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

/* =========================
   PROFILE / LANGUAGE
========================= */

app.put("/api/profile", auth, (req, res) => {
  try {
    const {
      name,
      shopName,
      language
    } = req.body;

    const current = db
      .prepare(`SELECT * FROM users WHERE id = ?`)
      .get(req.user.id);

    const newName =
      name !== undefined ? String(name).trim() : current.name;

    const newShop =
      shopName !== undefined
        ? String(shopName).trim()
        : current.shop_name;

    const newLanguage =
      language !== undefined
        ? String(language)
        : current.language;

    if (!newName || !newShop) {
      return res.status(400).json({
        error: "Name and shop name cannot be empty"
      });
    }

    if (!["Hindi", "English", "Bengali"].includes(newLanguage)) {
      return res.status(400).json({
        error: "Unsupported language"
      });
    }

    db.prepare(
      `UPDATE users
       SET name = ?, shop_name = ?, language = ?
       WHERE id = ?`
    ).run(
      newName,
      newShop,
      newLanguage,
      req.user.id
    );

    const updated = db
      .prepare(
        `SELECT id, name, shop_name, mobile, language, created_at
         FROM users
         WHERE id = ?`
      )
      .get(req.user.id);

    res.json({
      success: true,
      user: updated
    });
  } catch (error) {
    res.status(500).json({
      error: "Profile update failed"
    });
  }
});

/* =========================
   PURCHASE
========================= */

app.post("/api/purchases", auth, (req, res) => {
  try {
    const {
      product,
      quantity,
      cost,
      purchasePrice,
      date
    } = req.body;

    const cleanName = cleanProduct(product);

    const qty = positiveInteger(quantity, "quantity");

    const priceInput =
      cost !== undefined ? cost : purchasePrice;

    if (priceInput === undefined) {
      return res.status(400).json({
        error: "Purchase price is required"
      });
    }

    const costPaise = moneyToPaise(
      priceInput,
      "purchase price"
    );

    if (costPaise <= 0) {
      return res.status(400).json({
        error: "Purchase price must be greater than zero"
      });
    }

    const purchaseDate = validDate(date);

    const totalPaise = qty * costPaise;

    const result = db
      .prepare(
        `INSERT INTO purchase_lots
        (
          user_id,
          product,
          quantity,
          remaining_quantity,
          cost_paise,
          purchase_date
        )
        VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        req.user.id,
        cleanName,
        qty,
        qty,
        costPaise,
        purchaseDate
      );

    res.status(201).json({
      success: true,
      purchase: {
        id: Number(result.lastInsertRowid),
        product: cleanName,
        quantity: qty,
        cost: paiseToRupees(costPaise),
        total: paiseToRupees(totalPaise),
        date: purchaseDate
      }
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: error.message || "Purchase failed"
    });
  }
});

/* =========================
   STOCK
========================= */

app.get("/api/stock", auth, (req, res) => {
  try {
    const rows = db
      .prepare(
        `SELECT
          product,
          SUM(remaining_quantity) AS quantity,
          SUM(
            remaining_quantity * cost_paise
          ) AS inventory_value_paise
        FROM purchase_lots
        WHERE user_id = ?
        GROUP BY product
        ORDER BY product`
      )
      .all(req.user.id);

    res.json({
      success: true,
      stock: rows.map(row => ({
        product: row.product,
        quantity: Number(row.quantity || 0),
        inventoryValue: paiseToRupees(
          row.inventory_value_paise
        )
      }))
    });
  } catch (error) {
    res.status(500).json({
      error: "Could not load stock"
    });
  }
});

app.get("/api/stock/:product", auth, (req, res) => {
  try {
    const product = cleanProduct(req.params.product);

    const rows = db
      .prepare(
        `SELECT
          id,
          quantity,
          remaining_quantity,
          cost_paise,
          purchase_date
        FROM purchase_lots
        WHERE user_id = ?
          AND product = ?
          AND remaining_quantity > 0
        ORDER BY purchase_date ASC, id ASC`
      )
      .all(req.user.id, product);

    const quantity = rows.reduce(
      (sum, row) => sum + Number(row.remaining_quantity),
      0
    );

    const value = rows.reduce(
      (sum, row) =>
        sum +
        Number(row.remaining_quantity) *
          Number(row.cost_paise),
      0
    );

    res.json({
      success: true,
      product,
      quantity,
      inventoryValue: paiseToRupees(value),
      lots: rows.map(row => ({
        id: row.id,
        remainingQuantity: row.remaining_quantity,
        purchaseCost: paiseToRupees(row.cost_paise),
        purchaseDate: row.purchase_date
      }))
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

/* =========================
   SALE + FIFO
========================= */

const saleTransaction = db.transaction(
  ({
    userId,
    product,
    quantity,
    sellingPricePaise,
    saleDate
  }) => {
    const lots = db
      .prepare(
        `SELECT *
         FROM purchase_lots
         WHERE user_id = ?
           AND product = ?
           AND remaining_quantity > 0
         ORDER BY purchase_date ASC, id ASC`
      )
      .all(userId, product);

    const available = lots.reduce(
      (sum, lot) => sum + Number(lot.remaining_quantity),
      0
    );

    if (available < quantity) {
      throw new Error(
        `Insufficient stock. Available stock: ${available}`
      );
    }

    let remaining = quantity;
    let cogsPaise = 0;

    const layers = [];

    for (const lot of lots) {
      if (remaining <= 0) break;

      const take = Math.min(
        remaining,
        Number(lot.remaining_quantity)
      );

      const layerCost =
        take * Number(lot.cost_paise);

      cogsPaise += layerCost;

      layers.push({
        lotId: lot.id,
        quantity: take,
        costPaise: Number(lot.cost_paise)
      });

      db.prepare(
        `UPDATE purchase_lots
         SET remaining_quantity = remaining_quantity - ?
         WHERE id = ?`
      ).run(take, lot.id);

      remaining -= take;
    }

    const revenuePaise =
      quantity * sellingPricePaise;

    const grossProfitPaise =
      revenuePaise - cogsPaise;

    const saleResult = db
      .prepare(
        `INSERT INTO sales
        (
          user_id,
          product,
          quantity,
          selling_price_paise,
          revenue_paise,
          cogs_paise,
          gross_profit_paise,
          sale_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        userId,
        product,
        quantity,
        sellingPricePaise,
        revenuePaise,
        cogsPaise,
        grossProfitPaise,
        saleDate
      );

    const saleId = Number(saleResult.lastInsertRowid);

    const layerStmt = db.prepare(
      `INSERT INTO sale_fifo_layers
      (
        sale_id,
        purchase_lot_id,
        quantity,
        cost_paise
      )
      VALUES (?, ?, ?, ?)`
    );

    for (const layer of layers) {
      layerStmt.run(
        saleId,
        layer.lotId,
        layer.quantity,
        layer.costPaise
      );
    }

    return {
      saleId,
      revenuePaise,
      cogsPaise,
      grossProfitPaise,
      layers
    };
  }
);

app.post("/api/sales", auth, (req, res) => {
  try {
    const {
      product,
      quantity,
      sellingPrice,
      price,
      date
    } = req.body;

    const cleanName = cleanProduct(product);

    const qty = positiveInteger(quantity, "quantity");

    const priceInput =
      sellingPrice !== undefined
        ? sellingPrice
        : price;

    if (priceInput === undefined) {
      return res.status(400).json({
        error: "Selling price is required"
      });
    }

    const sellingPricePaise = moneyToPaise(
      priceInput,
      "selling price"
    );

    if (sellingPricePaise <= 0) {
      return res.status(400).json({
        error: "Selling price must be greater than zero"
      });
    }

    const saleDate = validDate(date);

    const result = saleTransaction({
      userId: req.user.id,
      product: cleanName,
      quantity: qty,
      sellingPricePaise,
      saleDate
    });

    res.status(201).json({
      success: true,
      sale: {
        id: result.saleId,
        product: cleanName,
        quantity: qty,
        sellingPrice: paiseToRupees(
          sellingPricePaise
        ),
        revenue: paiseToRupees(
          result.revenuePaise
        ),
        cogs: paiseToRupees(
          result.cogsPaise
        ),
        grossProfit: paiseToRupees(
          result.grossProfitPaise
        ),
        date: saleDate
      }
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: error.message || "Sale failed"
    });
  }
});

/* =========================
   EXPENSE
========================= */

app.post("/api/expenses", auth, (req, res) => {
  try {
    const {
      description,
      amount,
      date
    } = req.body;

    if (!description) {
      return res.status(400).json({
        error: "Expense description is required"
      });
    }

    const amountPaise = moneyToPaise(
      amount,
      "expense amount"
    );

    if (amountPaise <= 0) {
      return res.status(400).json({
        error: "Expense amount must be greater than zero"
      });
    }

    const expenseDate = validDate(date);

    const result = db
      .prepare(
        `INSERT INTO expenses
        (
          user_id,
          description,
          amount_paise,
          expense_date
        )
        VALUES (?, ?, ?, ?)`
      )
      .run(
        req.user.id,
        String(description).trim(),
        amountPaise,
        expenseDate
      );

    res.status(201).json({
      success: true,
      expense: {
        id: Number(result.lastInsertRowid),
        description: String(description).trim(),
        amount: paiseToRupees(amountPaise),
        date: expenseDate
      }
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

/* =========================
   KHATA
========================= */

app.post("/api/khata", auth, (req, res) => {
  try {
    const {
      customerName,
      type,
      amount,
      note,
      date
    } = req.body;

    if (!customerName) {
      return res.status(400).json({
        error: "Customer name is required"
      });
    }

    if (!["credit", "payment"].includes(type)) {
      return res.status(400).json({
        error: "Khata type must be credit or payment"
      });
    }

    const amountPaise = moneyToPaise(
      amount,
      "khata amount"
    );

    if (amountPaise <= 0) {
      return res.status(400).json({
        error: "Khata amount must be greater than zero"
      });
    }

    const entryDate = validDate(date);

    const result = db
      .prepare(
        `INSERT INTO khata
        (
          user_id,
          customer_name,
          type,
          amount_paise,
          note,
          entry_date
        )
        VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        req.user.id,
        String(customerName).trim(),
        type,
        amountPaise,
        note ? String(note).trim() : "",
        entryDate
      );

    res.status(201).json({
      success: true,
      entry: {
        id: Number(result.lastInsertRowid),
        customerName: String(customerName).trim(),
        type,
        amount: paiseToRupees(amountPaise),
        note: note ? String(note).trim() : "",
        date: entryDate
      }
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

app.get("/api/khata/:customer", auth, (req, res) => {
  try {
    const customer = String(
      req.params.customer
    ).trim();

    const entries = db
      .prepare(
        `SELECT *
         FROM khata
         WHERE user_id = ?
           AND LOWER(customer_name) = LOWER(?)
         ORDER BY entry_date ASC, id ASC`
      )
      .all(
        req.user.id,
        customer
      );

    let balancePaise = 0;

    const formatted = entries.map(entry => {
      if (entry.type === "credit") {
        balancePaise += Number(entry.amount_paise);
      } else {
        balancePaise -= Number(entry.amount_paise);
      }

      return {
        id: entry.id,
        customerName: entry.customer_name,
        type: entry.type,
        amount: paiseToRupees(entry.amount_paise),
        note: entry.note,
        date: entry.entry_date,
        balance: paiseToRupees(balancePaise)
      };
    });

    res.json({
      success: true,
      customer,
      balance: paiseToRupees(balancePaise),
      entries: formatted
    });
  } catch (error) {
    res.status(500).json({
      error: "Could not load Khata"
    });
  }
});

/* =========================
   DAILY REPORT
========================= */

app.get("/api/reports/daily", auth, (req, res) => {
  try {
    const date = validDate(req.query.date);

    const sales = db
      .prepare(
        `SELECT
          COALESCE(SUM(revenue_paise), 0) AS revenue,
          COALESCE(SUM(cogs_paise), 0) AS cogs,
          COALESCE(SUM(gross_profit_paise), 0) AS gross_profit,
          COALESCE(SUM(quantity), 0) AS quantity
         FROM sales
         WHERE user_id = ?
           AND sale_date = ?`
      )
      .get(req.user.id, date);

    const expenses = db
      .prepare(
        `SELECT
          COALESCE(SUM(amount_paise), 0) AS total
         FROM expenses
         WHERE user_id = ?
           AND expense_date = ?`
      )
      .get(req.user.id, date);

    const netProfit =
      Number(sales.gross_profit) -
      Number(expenses.total);

    res.json({
      success: true,
      date,
      sales: {
        revenue: paiseToRupees(sales.revenue),
        cogs: paiseToRupees(sales.cogs),
        grossProfit: paiseToRupees(
          sales.gross_profit
        ),
        quantity: Number(sales.quantity)
      },
      expenses: paiseToRupees(expenses.total),
      netProfit: paiseToRupees(netProfit)
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

/* =========================
   DAILY SALES
========================= */

app.get("/api/reports/daily-sales", auth, (req, res) => {
  try {
    const date = validDate(req.query.date);

    const rows = db
      .prepare(
        `SELECT
          id,
          product,
          quantity,
          selling_price_paise,
          revenue_paise,
          cogs_paise,
          gross_profit_paise,
          sale_date
         FROM sales
         WHERE user_id = ?
           AND sale_date = ?
         ORDER BY id ASC`
      )
      .all(req.user.id, date);

    const totalRevenue = rows.reduce(
      (sum, row) => sum + Number(row.revenue_paise),
      0
    );

    res.json({
      success: true,
      date,
      totalRevenue: paiseToRupees(totalRevenue),
      sales: rows.map(row => ({
        id: row.id,
        product: row.product,
        quantity: row.quantity,
        sellingPrice: paiseToRupees(
          row.selling_price_paise
        ),
        revenue: paiseToRupees(
          row.revenue_paise
        ),
        cogs: paiseToRupees(
          row.cogs_paise
        ),
        grossProfit: paiseToRupees(
          row.gross_profit_paise
        ),
        date: row.sale_date
      }))
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

/* =========================
   MONTHLY REPORT
========================= */

app.get("/api/reports/monthly", auth, (req, res) => {
  try {
    const now = new Date();

    const year =
      req.query.year !== undefined
        ? Number(req.query.year)
        : now.getUTCFullYear();

    const month =
      req.query.month !== undefined
        ? Number(req.query.month)
        : now.getUTCMonth() + 1;

    const { start, end } =
      monthRange(year, month);

    const sales = db
      .prepare(
        `SELECT
          COALESCE(SUM(revenue_paise), 0) AS revenue,
          COALESCE(SUM(cogs_paise), 0) AS cogs,
          COALESCE(SUM(gross_profit_paise), 0) AS gross_profit,
          COALESCE(SUM(quantity), 0) AS quantity
         FROM sales
         WHERE user_id = ?
           AND sale_date >= ?
           AND sale_date < ?`
      )
      .get(
        req.user.id,
        start,
        end
      );

    const expenses = db
      .prepare(
        `SELECT
          COALESCE(SUM(amount_paise), 0) AS total
         FROM expenses
         WHERE user_id = ?
           AND expense_date >= ?
           AND expense_date < ?`
      )
      .get(
        req.user.id,
        start,
        end
      );

    const netProfit =
      Number(sales.gross_profit) -
      Number(expenses.total);

    res.json({
      success: true,
      year,
      month,
      period: {
        start,
        endExclusive: end
      },
      sales: {
        revenue: paiseToRupees(sales.revenue),
        cogs: paiseToRupees(sales.cogs),
        grossProfit: paiseToRupees(
          sales.gross_profit
        ),
        quantity: Number(sales.quantity)
      },
      expenses: paiseToRupees(expenses.total),
      netProfit: paiseToRupees(netProfit)
    });
  } catch (error) {
    res.status(400).json({
      error: error.message
    });
  }
});

/* =========================
   ERROR HANDLER
========================= */

app.use((req, res) => {
  res.status(404).json({
    error: "API route not found"
  });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Dukaan Manager backend running on port ${PORT}`
  );
});
