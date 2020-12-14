const express = require('express')
const router = express.Router()
const bycrypt = require('bycryptjs')

let UserModel = require('../models/User.model')

const {isLoggedIn} = require ('../helpers/auth-helper');

router.post('/signup',(req, res)=>{
    const {username, email, password}= req.body;
    
    if (!username || !email || !password){
        res.status(500)
            .json({
                errorMessage: 'Please fill up all the details, they are mandatory'
            });
        return;
    }

    const emailRegExp = new RegExp(/^[a-z0-9](?!.*?[^\na-z0-9]{2})[^\s@]+@[^\s@]+\.[^\s@]+[a-z0-9]$/);
    if (!emailRegExp.test(email)){
        res.status(500)
        .json({
            errorMessage: 'Please enter a valid email, i.e: someone@whatever.com '
        });
        return;
    }

    const passwordRegExp = new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/);
    if (!passwordRegExp.test(password)) {
        res.status(500)
            .json({
                errorMessage: 'Password requires 8 characters with a number and an uppercase'
            });
        return;
    }

    bycrypt.genSalt(12)
        .then((salt)=>{
            bcrypt.hash(password, salt)
                .then((hassedPass)=>{
                    UserModel.create({email,username,hassedPass})
                    .then((user)=>{
                    user.hassedPass = "********";
                    req.session.loggedInUser = user;
                    res.status(200).json(user);
                    })
                .catch((err)=>{
                    if(err.code===11000) {
                        res.status(500)
                            .json({
                                errorMessage: 'username and/or email are in use, please try another one'
                            });
                            return;
                    }
                    else {
                        res.status(500)
                            .json({
                                errorMessage: 'Unexpected error, please try again'
                            });
                            return;
                        }
                    })
                });
        });
});

router.post('/signin', (req, res) => {
    const {email, password}=req.body;
    if(!email || !password){
        res.status(500).json({
            error: 'Please fill up the form'
        })
        return;
    }
    const emailRegExp = new RegExp(/^[a-z0-9](?!.*?[^\na-z0-9]{2})[^\s@]+@[^\s@]+\.[^\s@]+[a-z0-9]$/);
    if (!emailRegExp.test(email)){
        res.status(500).json ({
            error: 'Email format is not correct'
        })
        return;
    }

    UserModel.findOne({email})
        .then((userData)=>{
            bycrypt.compare(password, userData.passwordHash)
                .then((match)=>{
                    if (match){
                        userData.hassedPass = "********"
                        req.session.loggedInUser = userData;
                        res.status(200).json(userData)
                    }
                    else{
                        res.status(500).json({
                            error: 'Incorrect password'
                        })
                        return;
                    }
                })
                .catch(()=>{
                    res.status(500).json({
                        error: 'Email format is not correct',
                    })
                    return;
                });

        })
        .catch((err)=>{
            res.status(500).json({
                error: 'User does not exist, please Sign Up before you Sign In',
                message: err
            })
            return;
        });
});

router.post("/logout",(req,res)=>{
    req.session.destroy();
    res.status(204).send();
})

router.get("/user", isLoggedIn, (req, res, next)=>{
    res.status(200).json(req.session.loggedInUser);
});

module.exports = router;