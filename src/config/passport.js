const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
// const httpStatus = require('http-status');
const config = require('./config');
const { tokenTypes } = require('./tokens');
const { User } = require('../models');
const { tokenService } = require('../services');
// const ApiError = require('../utils/ApiError');

const jwtOptions = {
  // secretOrKey: config.jwt.secret,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKeyProvider: async (request, rawJwtToken, done) => {
    try {
      await tokenService.verifyToken(rawJwtToken, tokenTypes.ACCESS);
      return done(null, config.jwt.secret);
    } catch (error) {
      done(error, false);
    }
  },
};

const jwtVerify = async (payload, done) => {
  try {
    if (payload.type !== tokenTypes.ACCESS) {
      throw new Error('Invalid token type');
    }
    const user = await User.findById(payload.sub);
    if (!user) {
      return done(null, false);
    }
    done(null, user);
  } catch (error) {
    done(error, false);
  }
};

const jwtStrategy = new JwtStrategy(jwtOptions, jwtVerify);

module.exports = {
  jwtStrategy,
};
