'use strict';

const express = require('express');
const { check, validationResult }= require('express-validator');
const bcryptjs = require('bcryptjs');
const auth = require('basic-auth');

// const nameValidator = check('name')
//     .exists( {checkNull: true, checkFalsy: true})
//     .withMessage('Please provide a value for "name"');

const authenticateUser = (req, res, next) => {
    let message = null;
    const credentials = auth(req);
  
    // If the user's credentials are available...
    if (credentials) {
      const user = users.find(u => u.username === credentials.name);
  
      // If a user was successfully retrieved from the data store...
      if (user) {
        const authenticated = bcryptjs
          .compareSync(credentials.pass, user.password);
  
        // If the passwords match...
        if (authenticated) {
          console.log(`Authentication successful for username: ${user.username}`);
          req.currentUser = user;
        } else {
            message = `Authentication failure for username: ${user.username}`;
        }
      } else {
            message = `User not found for username: ${credentials.name}`;
      }
    } else {
        message = 'Auth header not found';
    }
  
    // If user authentication failed...
    if (message) {
      console.warn(message);
  
      // Return a response with a 401 Unauthorized HTTP status code.
      res.status(401).json({ message: 'Access Denied' });
    } else {
        next();
    }
};

// This array is used to keep track of user records
// as they are created.
const users = [];

// Construct a router instance.
const router = express.Router();

// Route that returns the current authenicated user.
router.get('/users', authenticateUser, (req, res) => {
    const user = req.currentUser;
    res.json({
        name: user.name,
        username: user.username,
    });
});

// Route that creates a new user.
router.post('/users', [ 
    check('name')
        .exists( {checkNull: true, checkFalsy: true})
        .withMessage('Please provide a value for "name"'),
    check('username')
        .exists( {checkNull: true, checkFalsy: true})
        .withMessage('Please provide a value for "username"'),
    check('password')
        .exists( {checkNull: true, checkFalsy: true})
        .withMessage('Please provide a value for "password"'),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        return res.status(400).json({errors: errorMessages})
    }
  // Get the user from the request body.
  const user = req.body;

  // Hash the new user's password.
  user.password = bcryptjs.hashSync(user.password); 

  // Add the user to the `users` array.
  users.push(user);

  // Set the status to 201 Created and end the response.
  res.status(201).end();
});

module.exports = router;