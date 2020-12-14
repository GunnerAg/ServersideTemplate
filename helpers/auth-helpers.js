const isLoggedIn = (req,res,next) =>{
    if (req.session.loggedInUser){
        next()
    }
    else {
        res.status(401).json({
            message : 'Unauthorized user',
            code : 401,
        })
    };
};

module.exports ={
    isLoggedIn,
}