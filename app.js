////////////  Passport.js to add Cookies and Sessions ///////////////

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

// SET UP SESSION------below code comes from express-session
app.use(session({
    secret: process.env.PASSPORT_LONG_SECRET,
    resave: false, 
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", true);
main().catch(err => console.log(err));

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB");
};

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    // thumbnail: String,
    // username: String,
    googleId: String,
    facebookId: String, 
    githubId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, { id: user.id, username: user.username, name: user.thumbnail });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});
  

// -------GOOGLE STRATEGY--------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate(
        { 
            googleId: profile.id
            // thumbnail: profile.photos[0].value,
            // username: profile.displayName 
        }, 
        function (err, user) {
            return cb(err, user);
        }
    );
  }
));

// -------FACEBOOK STRATEGY--------
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    enableProof: true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
    });
  }
));

// -------GITHUB STRATEGY--------
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
    res.render("home");
});


// -----GOOGLE AUTHENTICATION-----
app.get("/auth/google", 
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

// -----FACEBOOK AUTHENTICATION-----
app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: ["email"] })
);
 
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});

// -----GITHUB AUTHENTICATION-----
app.get('/auth/github', passport.authenticate('github', { scope: [ 'user:email' ] }));
 
app.get('/auth/github/secrets', 
    passport.authenticate('github', { failureRedirect: '/login' }), function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    }
);
 
 

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
        if (err) {
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/logout", function(req, res){

    req.logout(function(err) {
        if (err) { 
            return next(err); 
        }
        res.redirect("/");
    });

});

app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
    
});

app.post("/login", function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

app.listen(process.env.PORT, function(){
  console.log("Server started on port 3000.");
});











///////////// Hashing and Salting /////////////////////


// require('dotenv').config();
// const express = require("express");
// const bodyParser = require("body-parser");
// const ejs = require("ejs");
// const mongoose = require("mongoose");


// const bcrypt = require("bcrypt");
// const saltRounds = 10;

// // const md5 = require("md5");

// const app = express();

// app.use(express.static("public"));
// app.set("view engine", "ejs");
// app.use(bodyParser.urlencoded({extended: true}));

// mongoose.set('strictQuery', true);
// main().catch(err => console.log(err));

// async function main() {
//   await mongoose.connect('mongodb://127.0.0.1:27017/userDB');
// };

// const userSchema = new mongoose.Schema ({
//     email: String,
//     password: String
// });

// // const encrypt = require("mongoose-encryption");
// // const secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
// // userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });

// const User = new mongoose.model("User", userSchema);

// app.get("/", function(req, res){
//     res.render("home");
// });

// app.get("/login", function(req, res){
//     res.render("login");
// });

// app.get("/register", function(req, res){
//     res.render("register");
// });

// app.post("/register", function(req, res){

//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
    
//         newUser.save(function(err){
//             if (err){
//                 console.log(err);
//             } else {
//                 res.render("secrets");
//             }
//         });
//     });

    
// });

// app.post("/login", function(req, res){

//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({email: username}, function(err, foundUser){
//         if (err) {
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 bcrypt.compare(password, foundUser.password, function(err, result) {
//                     if(result === true){
//                         res.render("secrets");
//                     }
//                 });
//             }
//         }
//     });
// });

// app.listen(process.env.PORT, function(){
//   console.log("Server started on port 3000.");
// });
