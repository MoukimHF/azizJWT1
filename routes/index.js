const express = require('express');
const User = require('../models').User;
const _ = require('lodash');
const { check, validationResult } = require('express-validator/check');
const bcryptjs = require('bcryptjs');
const router = express.Router();
const jwt = require('jsonwebtoken');
const passport = require("passport");
const passportJWT = require("passport-jwt");
let ExtractJwt = passportJWT.ExtractJwt;
// helping functions
const getUser = async obj => {
  return await User.findOne({
  where: obj,
});
};
let JwtStrategy = passportJWT.Strategy;

let jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = "wowwow";
let strategy = new JwtStrategy(jwtOptions, async function(jwt_payload, next) {
  let user = await User.findOne({
  where: {id:jwt_payload.id},
})
  if (user) {
    next(null, user);
  } else {
    next(null, false);
  }
});
passport.use(strategy);

function asyncHandler(cb){
    return async(req, res, next) => {
      try {
        await cb(req, res, next)
      } catch(error){
        res.status(500).send(error);
      }
    }
}
router.get('/',(req,res,next)=>{
    res.json({
        message:"hello into the api route"
    })
})

    router.post('/signup', [
        check('emailAddress')
          .exists({ checkNull: true, checkFalsy: true })
          .withMessage('Please provide a value for "emailAddress"'),
        check('lastName')
          .exists({ checkNull: true, checkFalsy: true })
          .withMessage('Please provide a value for "lastName"'),
           check('password')
          .exists({ checkNull: true, checkFalsy: true })
          .withMessage('Please provide a value for "password"'),
      ], asyncHandler(async (req,res,next)=>{
        try{
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          const errorMessages = errors.array().map(error => error.msg);
          return res.status(400).json({ errors: errorMessages });
        }
  const user = req.body;
  // Hash the new user's password.
  user.password = bcryptjs.hashSync(user.password);
    const newUser =User.build({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        emailAddress: req.body.emailAddress,
        password: user.password,
    });
    
    await newUser.save();
    res.location('/')

     res.status(201).send({msg:`user with email address : ${newUser.emailAddress} created successfuly`}).end();
    }catch(e) {
      const messages = {};
     console.log(e.errors)
          e.errors.forEach((error) => {
              let message;
              switch (error.validatorKey) {
                  case 'isEmail':
                      message = 'Please enter a valid email';
                      break;
                  case 'is_null':
                      message = 'Please complete this field';
                      break;
                  case 'not_unique':
                      message = error.value + ' is taken. Please choose another one';
                      error.path = error.path.replace("_UNIQUE", "");
              }
              console.log(error.path)
              messages[error.path] = message;
          });
          res.status(400).json({message:messages})
      }
  
  }));
router.post("/login", async function(req, res, next) { 
    const { emailAddress, password } = req.body;
    if (emailAddress && password) {
      let user = await getUser({ emailAddress });
      if (!user) {
        res.status(401).json({ msg: "No such user found", user });
      }
      let payload = { id: user.id};
      if(bcryptjs.compareSync(password,user.password)){
          if(emailAddress=="ammarimedaziz2@gmail.com"){
            payload.role = "admin"
          }
          if(emailAddress=="ammarimedaziz1@gmail.com"){
            payload.role = "editor"
          }
        let token = jwt.sign(payload, jwtOptions.secretOrKey);
        res.header('x-auth-header', token).send({
          msg: `you are being authentified ${emailAddress}`,
          emailAddress,
          password,
          role:payload.role,
          token
        });
      } else {
        res.status(401).json({ msg: "Password is incorrect" });
      }
    }
  });

  router.get('/adminProtected', passport.authenticate('jwt', { session: false }), function(req, res) {
    const test = jwt.decode(req.headers.authorization.split(' ')[1])
    const {role} = test
    if(role=="admin")
      res.json({ msg: 'Congrats! You are an Admin'});
    else
      res.json({msg:"sorry you are not welcomed"})  
  });
  router.get('/editorProtected', passport.authenticate('jwt', { session: false }), function(req, res) {
    const test = jwt.decode(req.headers.authorization.split(' ')[1])
    const {role} = test
    if(role=="editor")
      res.json({ msg: 'Congrats! You are an Editor'});
    else
      res.json({msg:"sorry you are not welcomed"})  
  });
  router.get('/userProtected', passport.authenticate('jwt', { session: false }), function(req, res) {
      res.json({msg:"welcome"})  
  });
  module.exports = router;
