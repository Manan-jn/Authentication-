require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require("passport-google-oauth20");
const GitHubStrategy = require("passport-github2");
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

//MongoDB database
mongoose.connect("mongodb://localhost:27017/users", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    githubId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});


/////////////GOOGLE STRATEGY/////////////////
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/dashboard",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

//////////////GITHUB STRATEGY/////////////////////
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/dashboard"
},
    function (accessToken, refreshToken, profile, done) {
        User.findOrCreate({ githubId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

////////////GOOGLE ROUTES///////////////
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/dashboard",
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        //redirect to dashboard
        res.redirect("/dashboard");
    });

//////////GITHUB ROUTES//////////////
app.get('/auth/github',
    passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/dashboard',
    passport.authenticate('github', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect dashboard
        res.redirect('/dashboard');
    });

app.get("/login", function (req, res) {
    res.render("login");
});
app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/dashboard", function (req, res) {
    //check if the user is authenticated
    if (req.isAuthenticated()) {
        res.render("dashboard");
    }
    else {
        res.redirect("/login");
    }
})

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
})

app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/dashboard");
            })
        }
    })
});

app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/dashboard");
            });
        }
    });

});

app.listen(3000, function () {
    console.log("Server started on port 3000");
});