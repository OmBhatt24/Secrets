require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");

// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");



const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "my little secret",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB", () => {
    console.log("connected to mongoDB server");
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


// userSchema.plugin(encrypt, { secret: process.env.SECRET ,encryptedFields: ['password']});


const User = mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user._id);
    // if you use Model.id as your idAttribute maybe you'd want
    // done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLINT_ID,
    clientSecret: process.env.CLINT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));


app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });
app.get("/secrets", (req, res) => {
    User.find({secret:{$ne:null}},(err,foundUsers)=>{
        if(err) console.log(err);
        else{
            if(foundUsers){
                res.render("secrets",{usersWithSecrets:foundUsers});
            }
        }
    });
});

app.get("/submit",(req,res)=>{
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.render("login");
    }
});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,(err,foundUser)=>{
        if(err) console.log(err);
        else{
            if(foundUser){
                foundUser.secret= submittedSecret;
                foundUser.save(err=>{
                    if(!err) res.redirect("/secrets");
                });
            }
        }
    });    
})
app.get("/login", (req, res) => {
    res.render("login");
});
app.post("/login", (req, res) => {


    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });

    // Using bcrypt
    // User.findOne(
    //     { email: req.body.username },
    //     (err, foundUser) => {
    //         if (err) {
    //             console.log(err);
    //         } else {
    //             if (foundUser) {
    //                 bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
    //                     if(result){
    //                         res.render("secrets");
    //                     }
    //                 });

    //             }
    //         }
    //     });
});

app.get("/logout", (req, res) => {
    req.logout(err => {
        if (err) console.log(err);
        else {
            res.redirect("/");
        }
    });
})
app.get("/register", (req, res) => {
    res.render("register");
});
app.post("/register", (req, res) => {

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    })



    // Using bcrypt
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //     newUser.save(err => {
    //         if (err) {
    //             console.log(err);
    //         } else {
    //             res.render("secrets");
    //         }
    //     });
    // });
})

app.listen(3000, () => {
    console.log("server started at port 3000");
});
