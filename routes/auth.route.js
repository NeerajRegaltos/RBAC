const router = require("express").Router();
const User = require("../models/user.model");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login")
const { roles } = require("../utilis/constants")

router.get("/login", connectEnsureLogin.ensureLoggedOut({ redirectTo: "/" }), async (req, res, next) => {
    res.render("login");
});

router.post("/login", connectEnsureLogin.ensureLoggedOut({ redirectTo: "/" }), passport.authenticate("local", {
    //successRedirect: "/",
    successReturnToOrRedirect: "/",
    failureRedirect: "/auth/login",
    failureFlash: true
}));

router.get("/register", connectEnsureLogin.ensureLoggedOut({ redirectTo: "/" }), async (req, res, next) => {
    res.render("register");
});

router.post("/register", connectEnsureLogin.ensureLoggedOut({ redirectTo: "/" }), [
    body("email").trim().isEmail().withMessage("Email is Invalid"),
    body("password").trim().isLength(5).withMessage("Password Length must be more than 5 char"),
    body("password2").custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error("Password do not match")
        }
        return true;
    })
], async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            errors.array().forEach((error) => {
                req.flash("error", error.msg)
            })
            res.render("register", { email: req.body.email, messages: req.flash() })
            return;
        }
        const { email, password } = req.body;
        
        //Checking if user exist in databse
        const doesExist = await User.findOne({ email });
        if (doesExist) {
            req.flash("warning", "User already exist with this email");
            res.redirect("/auth/register");
            return;
        }

        //hashing plane text password
        const hashedPassword = await bcrypt.hash(password, 10);

        //Here i am saving user
        const user = new User({
            email,
            password: hashedPassword,
            role: email === process.env.ADMIN_EMAIL ? roles.admin : roles.client
        });
        await user.save();
        req.flash("success", `${user.email} is registered successfully,You can login now`)
        res.redirect("/auth/login")
    } catch (error) {
        next(error);
    }

});

router.get("/logout", connectEnsureLogin.ensureLoggedIn({ redirectTo: "/" }), async (req, res, next) => {
    req.logout();
    res.redirect("/");
})


module.exports = router;































// function ensureAuthenticated(req, res, next) {
//     if (req.isAuthenticated()) {
//         next();
//     } else {
//         res.redirect("/auth/login");
//     }
// }


// function ensureNOTAuthenticated(req, res, next) {
//     if (req.isAuthenticated()) {
//         res.redirect("back");
//     } else {
//         next();
//     }
// }