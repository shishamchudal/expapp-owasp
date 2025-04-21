// const { default: rateLimit } = require('express-rate-limit');
// const { default: helmet } = require('helmet');

const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user")
      mongoSanitize        =  require("express-mongo-sanitize"),
      rateLimit            =  require("express-rate-limit"),
      xss                  =  require("xss-clean"),
      helmet               =  require("helmet"),

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:false,
    cookie: {
        httpOnly:true,
        secure:false,
        maxAge: 1 * 60 * 1000 // 10 minutes
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================

app.use(mongoSanitize());

const limit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "Too many requests"
});
app.use('/routeName', limit);

app.use(express.json({ limit: '10kb' })); // Limit request body size to 10kb

app.use(xss()); // Sanitize user input to prevent XSS attacks

app.use(helmet()); // Set security HTTP headers

//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register");
});


app.post("/register", (req, res) => {
    const { username, password, email, phone } = req.body;

    const usernameRegex = /^[a-zA-Z0-9_]{5,15}$/;
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

    // Validate username and password on the server-side
    if (!usernameRegex.test(username)) {
        return res.render("register", { error: "Invalid username format. Must be 5-15 characters, alphanumeric or underscore." });
    }
    if (!passwordRegex.test(password)) {
        return res.render("register", { error: "Password too weak. Must be at least 8 characters, include uppercase, lowercase, number, and special character." });
    }

    User.register(new User({ username, email, phone }), password, function (err, user) {
        if (err) {
            console.log(err);
            return res.render("register", { error: "User registration failed." });
        }
        passport.authenticate("local")(req, res, function () {
            res.redirect("/login");
        });
    });
});

app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect("/");
});
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});