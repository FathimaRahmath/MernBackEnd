const express = require("express");
const router = express.Router();
const users = require("../Model/user");

//auth
const jwt = require('jsonwebtoken')

const bcrypt = require('bcryptjs');

const config = require('../Config/config');

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

// to create sign up route for user
router.post('/register', async (req, res) => {
    try {
        const data = req.body;
        console.log(data)
        let newUser = await users(data).save();
        console.log(newUser);
        res.status(200).send({ message: "User data added" })
    } catch (error) {
        console.log(error);
    }
})

// route for login
router.post('/login', async (req, res) => {
    let username = req.body.username;
    let password = req.body.password;

    const user = await users.findOne({ username });
    if (!user) {
        res.json({ message: 'user not found' })
    }
   
    try {
        if (user.password == password) {

            //auth
            let payload = { uname: username, pwd: password }
            let token = jwt.sign(payload, 'reactempapp');
            //res.json({message:"login success"})
            res.send({ message: 'login success', token: token })
        } else {
            res.json({message:"Login failed"})
        }
        
    } catch (error) {
        
    }
    
})

module.exports = router;