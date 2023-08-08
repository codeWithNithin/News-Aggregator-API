const jwt = require('jsonwebtoken');

const validateToken = async (req, res, next) => {
  let token;
  // get the token from the header
  const authHeader = req.headers.Authorization || req.headers.authorization;

  if (!authHeader) {
    res.status(401);
    throw new Error('Token is not valid');
  }

  if (authHeader.startsWith('Bearer')) {
    token = authHeader.split(' ')[1];

    if (!token) {
      res.status(401);
      throw new Error('Token is not valid or unauthorized');
    }

    // verify the token
    jwt.verify(token, 'admin@123', (err, decoded) => {
      if (err) {
        res.status(401);
        throw new Error('Token is not valid or unauthorized');
      }

      req.user = decoded.user;
      next();
    });
  }
};

module.exports = validateToken;
