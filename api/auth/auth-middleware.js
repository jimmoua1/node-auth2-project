const Users = require('../users/users-model');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    const token = req.headers.authorization;
    if (!token) {
       res.status(401).json({ message: 'we want a token!' })
    } else {
       jwt.verify(token, 'foo', (err, decoded) => {
          if (err) {
             res.status(401).json({ message: 'we want a GOOD token!' }, err.message );
          } else {
             req.decodedToken = decoded;
             next();
          }
       });
    }
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    try {
      const rows = Users.findBy({ username: req.body.username });
      if (!rows.length && role_name) { 
         next();
      } else {
         res.status(401).json('This is not for you');
      }
   } catch (error) {
      res.status(500).json({ message: 'something terrible happened!!'})
   } 
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    try {
      const rows = await Users.findBy({ username: req.body.username });
      if (rows.length) {
         req.userData = rows[0];
         next();         
      } else {
         res.status(404).json('Invalid credentials');
      }
   } catch (error) {
      res.status(500).json({ message: error.message });
   }  
}


const validateRoleName = role => (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
    if (req.decodedToken.role === role) {
      res.status(422).json({ message: 'Role name can not be admin' })
      next()
    } else {
      res.status(422).json({ message: 'Role name can not be longer than 32 chars' })
   }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
