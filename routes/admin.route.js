const router = require("express").Router();
const User = require("../models/user.model");
const mongoose = require("mongoose");
const { roles } = require("../utilis/constants");

router.get("/users", async (req, res, next) => {
    try {
        const users = await User.find();
        // res.send(users);
        res.render("manage-user", { users })
    } catch (error) {
        next(error);
    }
});


router.get("/user/:id", async (req, res, next) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            req.flash("error", "Invalid ID");
            res.redirect("/admin/users");
            return;
        }
        const person = await User.findById(id);
        res.render("profile", { person });
    } catch (error) {
        next(error);
    }
})



router.post("/update-role", async (req, res, next) => {
    try {
        const { id, role } = req.body;

        //checking for id and roles in req.body
        if (!id || !role) {
            req.flash("error", "Invalid Request");
            return res.redirect("back");
        }

        //check for vlid mongoose ObjectId
        if (!mongoose.Types.ObjectId.isValid(id)) {
            req.flash("error", "Invalid Id");
            return res.redirect("back");
        }

        //check for valid role
        const rolesArray = Object.values(roles);
        if (!rolesArray.includes(role)) {
            req.flash("error", "Invalid role");
            return res.redirect("back");
        }

        //admin cant remove themselves as an admin 
        if (req.user.id === id) {
            req.flash("error", "Admins cant remove themselves from Admin, Ask another admin");
            return res.redirect("back");
        }
        //finally update the user
        const user = await User.findByIdAndUpdate(
            id,
            { role },
            { new: true, runValidators: true });
        req.flash("info", `updated roll for ${user.email} to ${user.role}`
        );

        res.redirect("back");


    } catch (error) {
        next(error);
    }


})


module.exports = router;