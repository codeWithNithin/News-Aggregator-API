const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const resultData = require('../result.json');
const fs = require('fs');
const validateToken = require('../middleware/validateTokenHandler');

const router = express.Router();

router.post('/register', async (req, res) => {
  const { email, password, preferences } = req.body;
  if (!email || !password || preferences.length === 0) {
    res
      .status(400)
      .json({ message: 'Please provide all the required details' });
  }

  const result = JSON.parse(JSON.stringify(resultData));

  const userFound = result.users.find(
    (ele) => ele.email.toLowerCase() === email.toLowerCase()
  );

  if (userFound) {
    res.status(400).json({ message: 'User already exists' });
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const userId = result.users.length + 1;

  result.users.push({
    email,
    password: hashedPassword,
    preferences,
    userId,
  });

  fs.writeFileSync('./result.json', JSON.stringify(result), {
    encoding: 'utf8',
    flag: 'w',
  });

  res.status(200).json({
    message: 'User has been registered successfully',
    data: { user: { email, preferences, userId } },
  });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res
      .status(400)
      .json({ message: 'Please provide all the required details' });
  }

  const result = JSON.parse(JSON.stringify(resultData));

  const userFound = result.users.find(
    (ele) => ele.email.toLowerCase() === email.toLowerCase()
  );

  if (!userFound) {
    res.status(400).json({ message: 'User is not registered' });
  }

  const passwordMatched = await bcrypt.compare(password, userFound.password);

  if (!passwordMatched) {
    res.status(400).json({ message: 'Entered password is wrong' });
  }

  // send access token
  const accessToken = jwt.sign(
    {
      user: {
        email: userFound.email,
        id: userFound.userId,
        preferences: userFound.preferences,
      },
    },
    'admin@123',
    {
      expiresIn: '10h',
    }
  );

  res.status(200).json({
    message: 'Logged in succesfully',
    data: {
      accessToken,
      user: {
        userId: userFound.userId,
        email: userFound.email,
        preferences: userFound.preferences,
      },
    },
  });
});

router.get('/preferences', validateToken, (req, res) => {
  const result = JSON.parse(JSON.stringify(resultData));
  const user = req.user;
  const userData = result.users.find((ele) => ele.email === user.email);

  if (!userData) {
    res.status(400).json({ message: 'No preferences found' });
    return;
  }

  res.status(200).json({
    message: 'preferences successfully fetched',
    data: {
      preferences: userData.preferences,
    },
  });
});

router.put('/preferences', (req, res) => {
  const result = JSON.parse(JSON.stringify(resultData));
  const user = req.user;
  const index = result.users.findIndex((ele) => ele.email === user.email);
  result.users[index].preferences = req.body.preferences;
});

module.exports = router;
