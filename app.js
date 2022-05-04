require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const session = require("express-session");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODBATLAS);

const userSchema = new mongoose.Schema({
  googleId: String,
  facebookId: String,
  email: String,
  username: String,
  password: String,
  secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://secrets-ke.herokuapp.com/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "https://secrets-ke.herokuapp.com/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { facebookId: profile.id, username: profile.displayName },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.route("/").get((req, res) => {
  res.render("home");
});

app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })
  .post((req, res) => {
    User.register(
      { username: req.body.username },
      req.body.password,
      (err, user) => {
        if (!err) {
          passport.authenticate("local", { failureRedirect: "/register" })(
            req,
            res,
            () => {
              res.redirect("/secrets");
            }
          );
        } else {
          console.log(err);
          res.redirect("/register");
        }
      }
    );
  });

app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post((req, res) => {
    const newUser = new User({
      username: req.body.username,
      password: req.body.password,
    });
    req.login(newUser, (err) => {
      passport.authenticate("local", { failureRedirect: "/login" })(
        req,
        res,
        () => {
          res.redirect("/secrets");
        }
      );
    });
  });

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.route("/secrets").get((req, res) => {
  if (req.isAuthenticated()) {
    User.find({ secret: { $ne: null } }, (err, foundUsers) => {
      res.render("secrets", { secrets: foundUsers });
    });
  } else {
    res.redirect("/login");
  }
});

app
  .route("/submit")
  .get((req, res) => {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post((req, res) => {
    User.findOneAndUpdate(
      { username: req.user.username },
      { secret: req.body.secret },
      (err, foundUser) => {
        if (!err) {
          res.redirect("/secrets");
        } else {
          console.log(err);
          res.redirect("/submit");
        }
      }
    );
  });

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.listen(process.env.PORT, () => {
  console.log("Server is running");
});
