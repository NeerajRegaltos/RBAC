const passport = require("passport");
const localStrategy = require("passport-local").Strategy
const User = require("../models/user.model");

passport.use(
    new localStrategy({
        usernameField: "email",
        passwordField: "password"
    }, async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: "Username/Email not registered" });
            } else {
                //verify password here 
                const isMatch = await user.isValidPassword(password);
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: "Incorrect Email or Password" });
                }
            }
        } catch (error) {
            done(error);
        }
    })
);

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});