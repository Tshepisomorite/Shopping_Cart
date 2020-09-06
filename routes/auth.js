const express = require('express');
const {  check, body } = require('express-validator/check');

const authController = require('../controllers/auth');
const User = require('../models/user');
const router = express.Router();

router.get('/login', authController.getLogin);
router.get('/signup', authController.getSignup);
router.get('/reset', authController.getReset);
router.get('/reset/token', authController.getNewPassword);
router.post('/reset', authController.postReset);
router.post('/new-password', authController.postNewPassword);
router.post('/login', authController.postLogin);
router.post('/logout', authController.postLogout);
router.post(
    '/signup',
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email.')
      .normalizeEmail()
      .custom((value, { req }) => {
     return User.findOne({ email: value })
        .then(userDoc => {
          if (userDoc) {
            return Promise.reject('E-Mail exists already, please pick a different one.');
          }
        });
    
        // if (value === 'test@test.com') {
        //   throw new Error('This email address if forbidden.');
        // }
        // return true;
}),
body('password', 'Please enter a password with only numbers, and text, and atleast 5 characters.')
.isLength({min: 5})
.isAlphanumeric()
.trim(),
body('confirmPassword')
.trim()
.custom((value, {req}) =>
{
    if(value !== req.body.password) {
        throw new Error('Passwords have to match!');

    }
    return true;
}),
 authController.postSignup);

module.exports = router;