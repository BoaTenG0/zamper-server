import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt, { hash } from "bcrypt";
import cookieParser from "cookie-parser";
import { v4 as uuidv4 } from "uuid";
import cron from "node-cron";
import otpGenerator from "otp-generator";
import nodemailer from "nodemailer";

const salt = 10;
const app = express();
app.use(express.json());
const corsOptions = {
  origin: "https://threegolbank.org",
  methods: ["POST", "GET", "PUT", "OPTIONS"],
  credentials: true,
  exposedHeaders: ["set-cookie"],
};
app.use(cors(corsOptions));
app.use(cookieParser());
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://threegolbank.org");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

let db;

const handleDisconnect = () => {
  db = mysql.createConnection({
    host: "b5xrwsnezuojpt4kowfd-mysql.services.clever-cloud.com",
    user: "uop8wq9ursyq6yqm",
    password: "3evjXLxoRKurF8g1v0lL",
    database: "b5xrwsnezuojpt4kowfd",
    connectTimeout: 1000,
  });

  db.connect((err) => {
    if (err) {
      console.error("Error connecting to MySQL:", err);
      setTimeout(handleDisconnect, 2000);
    } else {
      console.log("MySQL connected");
    }
  });

  db.on("error", (err) => {
    console.error("MySQL error:", err);
    if (err.code === "PROTOCOL_CONNECTION_LOST") {
      handleDisconnect();
    } else {
      throw err;
    }
  });
};

handleDisconnect();
// const db = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "",
//   database: "threeColBank",
// });

// db.connect((err) => {
//   err ? console.log(err) : console.log("Mysql connected");
// });

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  console.log("Verifying user with token:", token);
  if (!token) {
    console.log("No token found. User not authenticated.");
    return res.json({ Error: "You are not authenticated" });
  } else {
    jwt.verify(token, "BroFrankJwt", (err, decoded) => {
      if (err) {
        console.log("Token verification failed:", err);
        return res.json({ Error: "Incorrect Token" });
      } else {
        req.user = decoded;
        console.log("Token verification successful. User:", req.user);
        next();
      }
    });
  }
};

cron.schedule(
  "0 * * * *",
  () => {
    const updateTransactionStatusQuery =
      "UPDATE transaction SET status = 'Success' WHERE user_id = ? AND status = 'Pending' ORDER BY id DESC LIMIT 1";
    db.query(
      updateTransactionStatusQuery,
      [user_id],
      (updateTransactionErr, updateTransactionResult) => {
        if (updateTransactionErr) {
          console.error(
            "Error updating transaction status:",
            updateTransactionErr
          );
        }
        console.log(
          "Transaction status updated to 'Success' for user",
          user_id
        );
      }
    );
  },
  {
    scheduled: true,
    timezone: "Africa/Accra",
  }
);

const generateOtp = () => {
  const OTP = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    specialChars: false,
  });
  return OTP;
};

app.post("/sendOtp", async (req, res) => {
  const { user_id } = req.body;

  // Check if user exists and get their email
  const checkUserQuery = "SELECT email FROM user WHERE user_id = ?";
  db.query(checkUserQuery, [user_id], async (checkUserErr, checkUserResult) => {
    if (checkUserErr) {
      console.error("Error checking user:", checkUserErr);
      return res.json({ Error: "Error checking user" });
    }
    if (checkUserResult.length === 0) {
      return res.json({ Error: "User does not exist" });
    }

    // Get user's email
    const userEmail = checkUserResult[0].email;
    console.log("🚀 ~ db.query ~ userEmail:", userEmail);
    // Generate OTP
    const otp = generateOtp();

    // Create a transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: "gboateng569@gmail.com",
        pass: "zttl oyik fljo enym ",
      },
    });

    // Message object
    const msg = {
      from: '"Three GloBank" <Three.GloBank@secretary.net>',
      to: userEmail,
      subject: "Three GloBank OTP verification",
      html: `
        <html>
          <head>
            <style>
              body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                padding: 20px;
              }
              .container {
                max-width: 600px;
                margin: 0 auto;
                background-color: #fff;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
              }
              h1 {
                color: #333;
              }
              p {
                color: #555;
                line-height: 1.5;
              }
              .logo {
                max-width: 150px;
              }
              .cta {
                background-color: #007bff;
                color: #fff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 5px;
                display: inline-block;
                margin-top: 20px;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <img src="https://res.cloudinary.com/dgjj1hsqo/image/upload/v1717090096/ThreeGolBank_yurgr2.svg" alt="Three GloBank Logo" class="logo">
              <h1>OTP Verification</h1>
              <p>Dear Customer,</p>
              <p>We are pleased to inform you that a One-Time Password (OTP) has been generated for your recent transaction with Three GloBank. Please use the following code to verify your transaction:</p>
              <p style="font-size: 24px; font-weight: bold;">Your OTP code is <b>${otp}</b></p>
              <p>OTP is valid for 5 minutes</p>
              <p>If you did not request this OTP, please ignore this email.</p>
              <p>Thank you for choosing Three GloBank for your banking needs.</p>
            </div>
          </body>
        </html>
      `,
    };

    try {
      const info = await transporter.sendMail(msg);

      console.log("Message sent: %s", info.messageId);
      console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
      // Store email, OTP, and timestamp in the otpSchema table
      const storeOtpQuery = "INSERT INTO otpschema (email, otp) VALUES (?, ?)";
      db.query(
        storeOtpQuery,
        [userEmail, otp],
        (storeOtpErr, storeOtpResult) => {
          if (storeOtpErr) {
            console.error("Error storing OTP:", storeOtpErr);
            return res.json({ Error: "Error storing OTP" });
          }
          return res.json({
            Status: "Success",
            email: userEmail,
          });
        }
      );
    } catch (error) {
      console.error("Error sending email:", error);
      res.json({ Error: "Error sending email" });
    }
  });
});

app.post("/verifyOtp", (req, res) => {
  const { email, otp, user_id } = req.body;
  const otpValidityDuration = 5 * 60 * 1000;

  const verifyOtpQuery =
    "SELECT otp, create_at FROM otpschema WHERE email = ? ORDER BY create_at DESC LIMIT 1";
  db.query(verifyOtpQuery, [email], (verifyOtpErr, verifyOtpResult) => {
    if (verifyOtpErr) {
      console.error("Error verifying OTP:", verifyOtpErr);
      return res.json({ Error: "Error verifying OTP" });
    }
    if (verifyOtpResult.length === 0 || verifyOtpResult[0].otp !== otp) {
      return res.json({ Status: "Failure", Error: "Invalid OTP" });
    }

    const currentTime = new Date();
    const otpTimestamp = new Date(verifyOtpResult[0].create_at);
    const timeDifference = currentTime - otpTimestamp;

    if (timeDifference > otpValidityDuration) {
      return res.json({ Status: "Failure", Error: "OTP has expired" });
    }

    // OTP verified successfully, update the transaction status
    const updateTransactionStatusQuery =
      "UPDATE transaction SET status = 'Success' WHERE user_id = ? AND status = 'Pending' ORDER BY id DESC LIMIT 1";
    db.query(
      updateTransactionStatusQuery,
      [user_id],
      (updateTransactionErr, updateTransactionResult) => {
        if (updateTransactionErr) {
          console.error(
            "Error updating transaction status:",
            updateTransactionErr
          );
          return res.json({ Error: "Error updating transaction status" });
        }
        console.log(
          "Transaction status updated to 'Success' for user",
          user_id
        );
        res.json({ Status: "Success" });
      }
    );
  });
});

app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "Success", user: req.user });
});

app.post("/register", (req, res) => {
  const email = req.body.email;
  const checkEmailQuery = "SELECT * FROM user WHERE email = ?";
  db.query(checkEmailQuery, [email], (checkErr, checkResult) => {
    if (checkErr) {
      return res.json({ Error: "Error checking email" });
    }
    if (checkResult.length > 0) {
      return res.json({ Error: "Email already exists" });
    }

    // If email doesn't exist, proceed with user registration
    const sql =
      "INSERT INTO user (`user_id`,`firstname`, `lastname`, `contact`, `email`, `country`, `password`) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
      if (err) return res.json({ Error: "Error for hashing password" });
      const userId = uuidv4();
      const values = [
        userId,
        req.body.firstname,
        req.body.lastname,
        req.body.contact,
        email,
        req.body.country,
        hash,
      ];
      db.query(sql, [values], (queryErr, result) => {
        if (queryErr) return res.json({ Error: "Error inserting data" });

        // Insert into account table after successful user registration
        const accountSql =
          "INSERT INTO account (user_id, balance, status) VALUES (?, ?, ?)";
        const accountValues = [userId, 0, "Active"];

        db.query(accountSql, accountValues, (accErr, accResult) => {
          if (accErr)
            return res.json({ Error: "Error inserting into account table" });

          return res.json({ Status: "Success" });
        });
      });
    });
  });
});

app.put("/editUser", (req, res) => {
  const { user_id, firstname, lastname, contact, email, country, password } =
    req.body;

  // Check if user exists
  const checkUserQuery = "SELECT * FROM user WHERE user_id = ?";
  db.query(checkUserQuery, [user_id], (checkUserErr, checkUserResult) => {
    if (checkUserErr) {
      console.error("Error checking user:", checkUserErr);
      return res.json({ Error: "Error checking user" });
    }
    if (checkUserResult.length === 0) {
      return res.json({ Error: "User does not exist" });
    }

    // If user exists, proceed with updating user information
    bcrypt.hash(password.toString(), salt, (err, hash) => {
      if (err) return res.json({ Error: "Error hashing password" });
      const updateUserQuery = `
        UPDATE user 
        SET firstname = ?, lastname = ?, contact = ?, email = ?, country = ?, password = ?
        WHERE user_id = ?
      `;
      const values = [
        firstname,
        lastname,
        contact,
        email,
        country,
        hash,
        user_id,
      ];
      db.query(updateUserQuery, values, (queryErr, result) => {
        if (queryErr) {
          console.error("Error updating data:", queryErr);
          return res.json({ Error: "Error updating data" });
        }
        return res.json({ Status: "Success" });
      });
    });
  });
});

app.post("/addCard", (req, res) => {
  const { user_id, number, name, expiry, cvc } = req.body;

  // Check if user exists
  const checkUserQuery = "SELECT * FROM user WHERE user_id = ?";
  db.query(checkUserQuery, [user_id], (checkUserErr, checkUserResult) => {
    if (checkUserErr) {
      console.error("Error checking user:", checkUserErr);
      return res.json({ Error: "Error checking user" });
    }
    if (checkUserResult.length === 0) {
      return res.json({ Error: "User does not exist" });
    }

    // Check if card number already exists
    const checkCardNumber = "SELECT * FROM card WHERE number = ?";
    db.query(checkCardNumber, [number], (checkCardErr, checkCardResult) => {
      if (checkCardErr) {
        console.error("Error checking card number:", checkCardErr);
        return res.json({ Error: "Error checking card number" });
      }
      if (checkCardResult.length > 0) {
        return res.json({ Error: "Card already exists" });
      }

      // If card doesn't exist, proceed with card insert
      const insertCardQuery =
        "INSERT INTO card (`user_id`, `name`, `number`, `expiry`, `cvc`) VALUES (?, ?, ?, ?, ?)";
      const values = [user_id, name, number, expiry, cvc];

      db.query(insertCardQuery, values, (insertCardErr, result) => {
        if (insertCardErr) {
          console.error("Error inserting data:", insertCardErr);
          return res.json({ Error: "Error inserting data" });
        }
        return res.json({ Status: "Success" });
      });
    });
  });
});

app.post("/Send", (req, res) => {
  const {
    user_id,
    amount,
    receiver,
    description,
    wallet_address,
    coin,
    network,
  } = req.body;

  // Check if user exists
  const checkUserQuery = "SELECT * FROM user WHERE user_id = ?";
  db.query(checkUserQuery, [user_id], (checkUserErr, checkUserResult) => {
    if (checkUserErr) {
      console.error("Error checking user:", checkUserErr);
      return res.json({ Error: "Error checking user" });
    }
    if (checkUserResult.length === 0) {
      return res.json({ Error: "User does not exist" });
    }

    // Get the current balance
    const getCurrentBalanceQuery =
      "SELECT balance FROM account WHERE user_id = ?";
    db.query(getCurrentBalanceQuery, [user_id], (balanceErr, balanceResult) => {
      if (balanceErr) {
        console.error("Error getting balance:", balanceErr);
        return res.json({ Error: "Error getting balance" });
      }

      const currentBalance = balanceResult[0].balance;
      if (currentBalance < amount) {
        return res.json({ Error: "Insufficient balance" });
      }

      // Update the balance
      const newBalance = currentBalance - amount;
      const updateBalanceQuery =
        "UPDATE account SET balance = ? WHERE user_id = ?";
      db.query(
        updateBalanceQuery,
        [newBalance, user_id],
        (updateBalanceErr, updateBalanceResult) => {
          if (updateBalanceErr) {
            console.error("Error updating balance:", updateBalanceErr);
            return res.json({ Error: "Error updating balance" });
          }

          const insertTransactionQuery =
            "INSERT INTO transaction (`user_id`, `receiver`, `description`, `type`, `status`, `wallet_addr`, `network`, `coin`, `amount`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
          const transactionValues = [
            user_id,
            receiver,
            description,
            "Debit",
            "Pending",
            wallet_address,
            network,
            coin,
            amount,
          ];
          db.query(
            insertTransactionQuery,
            transactionValues,
            (insertTransactionErr, result) => {
              if (insertTransactionErr) {
                console.error("Error inserting data:", insertTransactionErr);
                return res.json({ Error: "Error inserting data" });
              }

              // Fetch the updated balance
              db.query(
                getCurrentBalanceQuery,
                [user_id],
                (newBalanceErr, newBalanceResult) => {
                  if (newBalanceErr) {
                    console.error("Error getting new balance:", newBalanceErr);
                    return res.json({ Error: "Error getting new balance" });
                  }
                  const updatedBalance = newBalanceResult[0].balance;

                  // Send the updated balance in the response
                  return res.json({
                    Status: "Success",
                    newBalance: updatedBalance,
                  });
                }
              );
            }
          );
        }
      );
    });
  });
});

app.post("/Deposit", (req, res) => {
  const { user_id, amount, receiver, accountNumber, description } = req.body;

  // Check if user exists
  const checkUserQuery = "SELECT * FROM user WHERE user_id = ?";
  db.query(checkUserQuery, [user_id], (checkUserErr, checkUserResult) => {
    if (checkUserErr) {
      console.error("Error checking user:", checkUserErr);
      return res.json({ Error: "Error checking user" });
    }
    if (checkUserResult.length === 0) {
      return res.json({ Error: "User does not exist" });
    }

    // Insert the transaction
    const insertTransactionQuery =
      "INSERT INTO transaction (`user_id`, `receiver`, `description`, `type`, `status`, `amount`, `accountNumber`) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const transactionValues = [
      user_id,
      receiver,
      description,
      "Credit",
      "Pending",
      amount,
      accountNumber,
    ];
    db.query(
      insertTransactionQuery,
      transactionValues,
      (insertTransactionErr, result) => {
        if (insertTransactionErr) {
          console.error("Error inserting data:", insertTransactionErr);
          return res.json({ Error: "Error inserting data" });
        }

        // Check the status of the inserted transaction
        const checkTransactionStatusQuery =
          "SELECT status FROM transaction WHERE user_id = ? ORDER BY id DESC LIMIT 1";
        db.query(
          checkTransactionStatusQuery,
          [user_id],
          (transactionStatusErr, transactionStatusResult) => {
            if (transactionStatusErr) {
              console.error(
                "Error checking transaction status:",
                transactionStatusErr
              );
              return res.json({ Error: "Error checking transaction status" });
            }

            const transactionStatus = transactionStatusResult[0].status;

            if (transactionStatus === "Success") {
              // Get the current balance
              const getCurrentBalanceQuery =
                "SELECT balance FROM account WHERE user_id = ?";
              db.query(
                getCurrentBalanceQuery,
                [user_id],
                (balanceErr, balanceResult) => {
                  if (balanceErr) {
                    console.error("Error getting balance:", balanceErr);
                    return res.json({ Error: "Error getting balance" });
                  }

                  const currentBalance = balanceResult[0].balance;

                  // Update the balance
                  const newBalance = currentBalance + parseFloat(amount);
                  const updateBalanceQuery =
                    "UPDATE account SET balance = ? WHERE user_id = ?";
                  db.query(
                    updateBalanceQuery,
                    [newBalance, user_id],
                    (updateBalanceErr, updateBalanceResult) => {
                      if (updateBalanceErr) {
                        console.error(
                          "Error updating balance:",
                          updateBalanceErr
                        );
                        return res.json({ Error: "Error updating balance" });
                      }

                      // Send the updated balance in the response
                      return res.json({
                        Status: "Success",
                        newBalance: newBalance,
                      });
                    }
                  );
                }
              );
            } else {
              // Transaction status is Pending, no need to update the balance
              return res.json({ Status: "Pending", newBalance: null });
            }
          }
        );
      }
    );
  });
});

app.get("/getCard/:user_id", (req, res) => {
  const user_id = req.params.user_id;
  const getCardQuery = "SELECT * FROM card WHERE user_id = ?";

  db.query(getCardQuery, [user_id], (err, result) => {
    if (err) {
      console.error("Error fetching card details:", err);
      return res.json({ Error: "Error fetching card details" });
    }
    if (result.length === 0) {
      return res.json({ Error: "No cards found for this user" });
    }
    return res.json({ Status: "Success", cards: result });
  });
});

app.get("/transactions/:user_id", (req, res) => {
  const user_id = req.params.user_id;
  const getCardQuery = "SELECT * FROM transaction WHERE user_id = ?";

  db.query(getCardQuery, [user_id], (err, result) => {
    if (err) {
      console.error("Error fetching transactions :", err);
      return res.json({ Error: "Error fetching transactions" });
    }
    if (result.length === 0) {
      return res.json({ Error: "No transactions found for this user" });
    }
    return res.json({ Status: "Success", transactions: result });
  });
});

app.get("/balance/:user_id", (req, res) => {
  const user_id = req.params.user_id;
  const getCardQuery = "SELECT * FROM account WHERE user_id = ?";

  db.query(getCardQuery, [user_id], (err, result) => {
    if (err) {
      console.error("Error fetching account details:", err);
      return res.json({ Error: "Error fetching account details" });
    }
    if (result.length === 0) {
      return res.json({ Error: "No account found for this user" });
    }
    return res.json({ Status: "Success", account: result });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM user WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Error Logging in from server" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err) return res.json({ Error: "Password Compare Error" });
          if (response) {
            // const name = data[0].firstname;
            const user = {
              id: data[0].id,
              user_id: data[0].user_id,
              firstname: data[0].firstname,
              lastname: data[0].lastname,
              email: data[0].email,
              country: data[0].country,
              contact: data[0].contact,
            };
            const token = jwt.sign({ user }, "BroFrankJwt", {
              expiresIn: "1d",
            });
            res.cookie("token", token, {
              httpOnly: true,
              secure: true,
              sameSite: "None",
            });

            console.log("Login successful. User:", user);
            return res.json({ Status: "Login Successful", token });
          } else {
            console.log("Invalid password for user:", req.body.email);
            return res.json({ Error: "Invalid Password" });
          }
        }
      );
    } else {
      return res.json({ Error: "Email does not exist" });
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
  });
  return res.json({ Status: "Success" });
});

// GET route
app.get("/all", (req, res) => {
  res.send("hii");
});
app.listen(8082, () => {
  console.log("🚀 ~ app.listening ~ on port ~ 8082:");
});
