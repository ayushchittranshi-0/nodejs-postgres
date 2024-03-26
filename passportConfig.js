const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

const authenticateUser = (email, password, done) => {
  console.log("reached authenticateUser", email, password);

  pool.query(`SELECT * FROM users WHERE email=$1 `, [email], (err, results) => {
    if (err) throw err;
    console.log("results++", results.rows);

    if (results.rows.length > 0) {
      const user = results.rows[0];

      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) throw err;

        if (isMatch) {
          console.log("Logging in matched user.");
          return done(null, user);
        } else {
          return done(null, false, { message: "Password is not correct." });
        }
      });
    } else {
      return done(null, false, {
        message: "User is not register. Please register to login.",
      });
    }
  });
};

const initialize = (passport) => {
  passport.use(
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
      },
      authenticateUser,
    ),
  );
  passport.serializeUser((user, done) => {
    return done(null, user.id);
  });
  passport.deserializeUser((id, done) => {
    pool.query(`SELECT * FROM users WHERE id=$1`, [id], (err, results) => {
      if (err) throw err;

      return done(null, results.rows[0]);
    });
  });
};

module.exports = initialize;
