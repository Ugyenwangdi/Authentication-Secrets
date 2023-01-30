////////////  Passport.js to add Cookies and Sessions ///////////////

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: process.env.PASSPORT_LONG_SECRET,
    resave: false, 
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
main().catch(err => console.log(err));

async function main() {
  await mongoose.connect('mongodb://127.0.0.1:27017/userDB');
};

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    if (req.isAuthenticated()){
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){

    req.logout(function(err) {
        if (err) { 
            return next(err); 
        }
        res.redirect('/');
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
