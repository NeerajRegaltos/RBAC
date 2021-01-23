const express = require("express");
const createHttpError = require("http-errors");
const morgan = require("morgan");
const mongoose = require("mongoose");
require("dotenv").config();
const session = require("express-session");
const connectFlash = require("connect-flash");
const passport = require("passport");
const connectMongo = require("connect-mongo");
const connectEnsureLogin = require("connect-ensure-login")
const { roles } = require("./utilis/constants");

//Initialization
const app = express();
app.use(morgan("dev"));
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//conntect mongo
const MongoStore = connectMongo(session);


//Init Session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure:true
        // httpOnly: true
    },
    store: new MongoStore({ mongooseConnection: mongoose.connection }),
}));

app.use((passport.initialize()))
app.use(passport.session()); 77
require("./utilis/passport.auth");


app.use((req, res, next) => {
    res.locals.user = req.user;
    next();
})

//connect flash 
app.use(connectFlash());
app.use((req, res, next) => {
    res.locals.messages = req.flash();
    next();
})


//Routes
app.use("/", require("./routes/index.route"));
app.use("/auth", require("./routes/auth.route"));
app.use("/admin", connectEnsureLogin.ensureLoggedIn({ redirectTo: "/auth/login" }), ensureAdmin, require("./routes/admin.route"));
app.use("/user", connectEnsureLogin.ensureLoggedIn({ redirectTo: "/auth/login" }), require("./routes/user.route"));


app.use((req, res, next) => {
    next(createHttpError.NotFound());
});

app.use((error, req, res, next) => {
    error.status = error.status || 500
    res.status(error.status);
    res.render("error_40x", { error });
});

const PORT = process.env.PORT || 3000;


mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    useFindAndModify: false
})
    .then(() => {
        console.log("Connection Established to DB");
        app.listen(PORT, () => {
            console.log(`Server running on ${PORT}`);
        });
    })
    .catch(err => {
        console.log(err.message);
    })


// function ensureAuthenticated(req, res, next) {
//     if (req.isAuthenticated()) {
//         next();
//     } else {
//         res.redirect("/auth/login");
//     }
// }

function ensureAdmin(req, res, next) {
    if (req.user.role === roles.admin) {
        next();
    }
    else {
        req.flash("warning", "This route is only for admin");
        res.redirect("/");
    }
}

function ensureModerator(req,res,next){
    if (req.user.role === roles.moderator) {
        next();
    }
    else {
        req.flash("warning", "This route is only for admin");
        res.redirect("/");
    }
}