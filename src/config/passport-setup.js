'use strict';

const passport = require('passport');
const { userService } = require('../services/user.service');
const { User } = require('../models/User');
const { tokenService } = require('../services/token.service');
const bcrypt = require('bcrypt');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const foundUser = await userService.getUserById(parseInt(id));

    done(null, foundUser);
  } catch (error) {
    done(error, null);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://auth-backend-hxdm.onrender.com/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      // const { name, email } = profile._json;

      try {
      //   const user = await userService.getUserByEmail(email);

      //   if (user) {
      //     const isUserAuthorized = await tokenService.getByUserId(user.id);

      //     if (isUserAuthorized) {
      //       return done(null, false, {
      //         message: 'User with this email already exists!',
      //         redirectUrl: 'http://localhost:5173/authentication-app',
      //       });
      //     }
      //   }

      //   const hashedPassword = await bcrypt.hash('1234567', 10);

      //   const newUser = await User.create({
      //     name,
      //     email,
      //     password: hashedPassword,
      //   });

      //   await tokenService.save(newUser.id, refreshToken);

      //   Object.assign(profile, { accessToken, id: newUser.id });

        return done(null, profile);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);
