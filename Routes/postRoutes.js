const express = require("express");
const router = express.Router();
const posts = require("../Model/post")



//auth
const jwt=require('jsonwebtoken')


router.use(express.json());
router.use(express.urlencoded({ extended: true }));

//auth
function verifyToken(req,res,next) {
    const token = req.headers.token;
    try {
        if (!token) throw 'Unauthorized access';
        let payload = jwt.verify(token, 'reactempapp')
        if (!payload) throw 'Unauthorized access'
        next()
    } catch (error) {
      res.status(404).send('Caught in error')  
    }
}


// to create sign up route
router.post('/new',verifyToken ,async (req, res) => {
    try {
        const post = req.body;
        console.log(post)
        let newPost = await posts(post).save();
        console.log(newPost);
        res.status(200).send({ message: "Post data added" })
    } catch (error) {
        console.log(error);
    }
})

module.exports=router