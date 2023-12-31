'use strict';

const express = require('express');
const { userController } = require('../controllers/user.controller');
const { catchError } = require('../middlewares/catchError');

const userRouter = express.Router();

userRouter.get(
  '/',
  catchError(userController.getAllUsers)
);

module.exports = { userRouter };
