const session = require("express-session");

const authHandler = require('../controllers/auth');
module.exports = (req, res, next) => {
    if (!req.session.isLoggedIn  ) {
        // || new Date().getTime() > req.session.Date.getTime()
        //  authHandler.postLogout(req, res , next);  
    res.redirect('/login');
    }
    next();
}