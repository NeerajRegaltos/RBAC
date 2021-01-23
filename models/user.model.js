const createHttpError = require("http-errors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { roles } = require("../utilis/constants")

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        lowercase: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: [roles.client, roles.moderator, roles.admin],
        default: "CLIENT"
    }
});

userSchema.methods.isValidPassword = async function (password) {
    try {
        return await bcrypt.compare(password, this.password);
    } catch (error) {
        throw createHttpError.InternalServerError(error.message);
    }
}

const User = mongoose.model("user", userSchema);

module.exports = User;