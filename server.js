const express = require("express");
const app = express();

let users = [];

app.use(express.json());

// ساخت کاربر
app.post("/create-user", (req, res) => {
  let code = "PMX" + Math.floor(100000 + Math.random() * 900000);

  let user = {
    code,
    balance: 0
  };

  users.push(user);

  res.json(user);
});

// شارژ حساب
app.post("/charge", (req, res) => {
  let { code, amount } = req.body;

  let user = users.find(u => u.code === code);

  if (user) {
    user.balance += amount;
    res.send("شارژ شد");
  } else {
    res.send("کاربر پیدا نشد");
  }
});

app.listen(3000, () => console.log("Server running"));