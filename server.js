const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const app = express();

const path = require("path");

const PORT = process.env.PORT || 3003;

const initializePassport = require("./passportConfig");
initializePassport(passport);

//middleware
app.use("/assets", express.static(__dirname + "/static"));
app.use(express.urlencoded({ extended: false }));
// Set the views directory to 'templates'
app.set("views", path.join(__dirname, "templates"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
  }),
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

const checkAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return res.redirect("/users/dashboard");
  next();
};

const checkNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect("/users/login");
};
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/users/login", checkAuthenticated, (req, res) => {
  res.render("login");
});

app.get("/users/register", checkAuthenticated, (req, res) => {
  res.render("register");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user.name });
});

app.get("/users/logout", (req, res) => {
  req.logOut((err) => {
    if (err) {
      throw err;
    }
    req.flash("success_message", "You have logged out.");
    res.redirect("/users/login");
  });
});

app.post("/users/register", async (req, res) => {
  let { name, password, password2, email } = req.body;
  let errors = [];

  if (!name || !password || !password2 || !email)
    errors.push({ message: "Please enter all fields." });

  if (password.length < 6)
    errors.push({ message: "Password should be atleast 6 characters." });

  if (password !== password2)
    errors.push({ message: "Password do not match." });

  if (errors.length > 0) res.render("register", { errors });
  else {
    // Validation has passed
    let hashedPassword = await bcrypt.hash(password, 10);
    console.log("hashedPassword is", hashedPassword);

    pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
      (err, results) => {
        if (err) throw err;
        console.log("results of query are ", results.rows);
        if (results.rows.length > 0) {
          errors.push({ message: "Email already registered." });
          console.log("errors", errors);
          res.render("register", { errors });
        } else {
          pool.query(
            `INSERT INTO users (name, email, password) 
            VALUES ($1, $2, $3) 
            RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) throw err;
              console.log("results", results.rows);
              req.flash(
                "success_message",
                "You are now registered. Please log in.",
              );
              res.redirect("/users/login");
            },
          );
        }
      },
    );
  }
});

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  }),
);

app.listen(PORT, () => {
  console.log(`Server running on PORT ${PORT}`);
});
