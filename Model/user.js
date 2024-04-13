const mongoose = require('mongoose');

const schema = mongoose.Schema({
    email: String,
    password: String,
    role:String

})

const userModel = mongoose.model('user', schema)
module.exports = userModel;