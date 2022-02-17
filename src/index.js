const express = require('express');
const helmet = require('helmet');
const session = require('cookie-session');
const { body, validationResult } = require('express-validator');

const app = express();

const expirationDate = new Date(Date.now() + 60 * 60 * 1000);

app
  .use(express.json())
  .use(session({
    name: 'session',
    keys: ['key1', 'key2'],
    cookie: {   
      secure: true,
      httpOnly: true,
      domain: 'example.com',
      path: 'foo/bar',
      expires: expirationDate
    } 
  }))
  .use(helmet());

app.post(
  '/user',
  body('username').isEmail(),
  body('password').isLength({ min: 5 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    User.create({
      username: req.body.username,
      password: req.body.password,
    }).then(user => res.json(user));
  },
); 

app.post(
  '/comment',
  body('email').isEmail().normalizeEmail(),
  body('text').not().isEmpty().trim().escape(),
  body('notifyOnReply').toBoolean(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    Comment.create({
      email: req.body.email,
      text: req.body.text,
      notifyOnReply: req.body.notifyOnReply,
    }).then(comment => res.json(comment));
  },
);

app.listen(3333);