var mongoose = require('mongoose');
var bcrypt = require('bcrypt');
var hash = require('hash.js');
var md5 = require('md5');
var pbkdf2 = require('pbkdf2');
var randombytes = require('randombytes');
var scrypt = require('scrypt-async');

var UserSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    trim: true
  },
  username: {
    type: String,
    unique: true,
    required: true,
    trim: true
  },
  password: {
    type: String,
  },
  password_plain: {
    type: String,
  },
  password_bcrypt: {
    type: String,
  },
  password_md5: {
    type: String,
  },
  password_pbkdf2: {
    type: Object,
  },
  password_scrypt: {
    type: Object,
  },
});

//authenticate input against database
UserSchema.statics.authenticate = function (email, password, callback) {
  User.findOne({ email: email })
    .exec(function (err, user) {
      if (err) {
        return callback(err)
      } else if (!user) {
        var err = new Error('User not found.');
        err.status = 401;
        return callback(err);
      }
      bcrypt.compare(password, user.password_bcrypt, function (err, result) {
        if (result === true) {
          return callback(null, user);
        } else {
          return callback();
        }
      })
    });
}

//hashing a password before saving it to the database
UserSchema.pre('save', function (next) {
  var user = this;
  bcrypt.hash(user.password, 10, function (err, hash) {
    if (err) {
      return next(err);
    }
    user.password_bcrypt = hash;
    next();
  })
  user.password_plain = user.password;
  user.password_md5 = md5(user.password);
  const pbkdf2_iterations = 1000;
  const pbkdf2_salt = randombytes(16).toString('hex');
  // using sha1 to validate online against:
  // - https://www.freecodeformat.com/pbkdf2.php
  // - http://www.anandam.name/pbkdf2/
  const pbkdf2_algo = 'sha1';
  user.password_pbkdf2 = {
      iterations: pbkdf2_iterations,
      salt: pbkdf2_salt,
      algo: pbkdf2_algo,
      key: pbkdf2.pbkdf2Sync(user.password, pbkdf2_salt, pbkdf2_iterations, 32, pbkdf2_algo).toString('hex')
  };
  const scrypt_N = 1<<11;
  const scrypt_r = 8;
  const scrypt_p = 1;
  const scrypt_salt = randombytes(16).toString('hex');
  // how to validate scrypt online
  // - http://dchest.github.io/scrypt-async-js/
  // - http://ricmoo.github.io/scrypt-js/
  scrypt(user.password, scrypt_salt, {
    N: scrypt_N,
    r: scrypt_r,
    p: scrypt_p,
    dkLen: 32,
    encoding: 'hex'
  }, function(derivedKey) {
    user.password_scrypt = {
        salt: scrypt_salt,
        N: scrypt_N,
        r: scrypt_r,
        p: scrypt_p,
        key: derivedKey,
    };
  });
});


var User = mongoose.model('User', UserSchema);
module.exports = User;
