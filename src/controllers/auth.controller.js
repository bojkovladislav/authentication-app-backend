'use strict';

const { ApiError } = require('../exceptions/api.error.js');
const {
  validatePassword,
  validateEmail,
} = require('../utils/validationData.js');
const { userService } = require('../services/user.service.js');
const { jwtService } = require('../services/jwt.service.js');
const { tokenService } = require('../services/token.service.js');
const bcrypt = require('bcrypt');

const checkUserExistence = (user, id) => {
  if (!user) {
    throw ApiError.notFound(`There's no such user with id ${id}`);
  }
};

const getSuccessfulMessage = (user, updatedValueName) => {
  return {
    message: `Your ${updatedValueName} has been successfully updated!`,
    updatedUser: user,
  };
};

const prepareTokens = async (user, res) => {
  const userData = userService.normalize(user);
  const accessToken = jwtService.generateToken(
    userData,
    'JWT_ACCESS_SECRET',
    '30m'
  );
  const refreshToken = jwtService.generateToken(
    userData,
    'JWT_REFRESH_SECRET',
    `${30 * 24 * 60}m`
  );

  await tokenService.save(user.id, refreshToken);

  res.cookie(`refreshToken_${user.id}`, refreshToken, {
    maxAge: 30 * 24 * 60 * 1000,
    sameSite: 'none',
    secure: true,
    httpOnly: true,
  });

  return accessToken;
};

const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    throw ApiError.badRequest('Name, email and password are required!');
  }

  const errors = {
    password: validatePassword(password),
    email: validateEmail(email),
  };

  if (errors.password || errors.email) {
    throw ApiError.badRequest('Validation error!', errors);
  }

  await userService.register(name, email, password);

  res.send({ message: "You've been successfully registered!" });
};

const activate = async (req, res) => {
  const { activationToken } = req.params;

  const foundUser = await userService.getUserByActivationToken(activationToken);

  if (!foundUser) {
    throw ApiError.notFound('User was not found!');
  }

  foundUser.activationToken = null;

  await foundUser.save();

  await sendAuthentication(res, foundUser);

  res.send(foundUser);
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const errorMessage = 'Either your email or password are not correct!';
  const validationError = ApiError.badRequest('Validation error!', {
    email: errorMessage,
    password: errorMessage,
  });

  if (!email || !password) {
    throw ApiError.badRequest(
      'You should provide email and password in order to log in!'
    );
  }

  const foundUser = await userService.getUserByEmail(email);

  if (!foundUser) {
    throw validationError;
  }

  const passwordsMatch = await bcrypt.compare(password, foundUser.password);

  if (!passwordsMatch) {
    throw validationError;
  }

  await sendAuthentication(res, foundUser);
};

const logout = async (req, res) => {
  const { userId } = req.params;

  await tokenService.remove(userId);
  res.clearCookie(`refreshToken_${userId}`);

  res.sendStatus(204);
};

const refresh = async (req, res) => {
  const { oldAccessToken } = req.body;
  const { userId } = req.params;
  const refreshToken = req.cookies[`refreshToken_${userId}`];

  const userData = jwtService.verifyToken(refreshToken, 'JWT_REFRESH_SECRET');
  const oldUserData = jwtService.verifyToken(
    oldAccessToken,
    'JWT_ACCESS_SECRET'
  );

  if (!userData) {
    throw ApiError.unAuthorized();
  }

  if (oldUserData) {
    throw ApiError.badRequest({
      message: "You don't need to change your access token",
    });
  }

  if (userData && !oldUserData) {
    const newAccessToken = jwtService.generateToken(
      userService.normalize(userData),
      'JWT_ACCESS_SECRET',
      '30s'
    );

    res.status(200).send({
      message: 'Your new access token is ready to use!',
      accessToken: newAccessToken,
    });
  }
};

const sendAuthentication = async (res, user) => {
  const accessToken = await prepareTokens(user, res);

  res.send({
    user: userService.normalize(user),
    accessToken,
  });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw ApiError.badRequest('Email is required!');
  }

  const errorInEmail = validateEmail(email);

  if (errorInEmail) {
    throw ApiError.badRequest('Email validation error', {
      email: errorInEmail,
    });
  }

  await userService.forgotPassword(res, email);

  res.send('Email with password reset has been sent!');
};

const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  if (!resetToken) {
    throw ApiError.notFound('Missing reset token!');
  }

  if (!newPassword) {
    throw ApiError.badRequest('You should provide a new password!');
  }

  const errorInPassword = validatePassword(newPassword);

  if (errorInPassword) {
    throw ApiError.badRequest('Validation error', {
      newPassword: errorInPassword,
    });
  }

  const foundUser = await userService.resetPassword(resetToken, newPassword);

  res.clearCookie('resetToken');

  res.send({
    message: 'The password has been successfully changed!',
    updatedUser: foundUser,
  });
};

const updateName = async (req, res) => {
  const { id } = req.params;
  const { updatedName } = req.body;

  const foundUser = await userService.getUserById(id);

  checkUserExistence(foundUser, id);

  if (!updatedName) {
    throw ApiError.badRequest('You need to provide an updated name!');
  }

  if (updatedName === foundUser.name) {
    throw ApiError.badRequest('Validation error!', {
      name: 'Your updated name is the same as the old one!',
    });
  }

  await userService.updateName(foundUser, updatedName);

  res.status(200).send(getSuccessfulMessage(foundUser, 'name'));
};

const updatePassword = async (req, res) => {
  const { id } = req.params;
  const { oldPassword, newPassword, confirmation } = req.body;
  const errors = {};

  if (!(oldPassword && newPassword && confirmation)) {
    throw ApiError.badRequest(
      'You need to provide old password, new password and confirmation!'
    );
  }

  const foundUser = await userService.getUserById(id);

  checkUserExistence(foundUser, id);

  if (!(await bcrypt.compare(oldPassword, foundUser.password))) {
    errors.oldPassword = 'Password is incorrect!';
  }

  if (newPassword === oldPassword) {
    errors.newPassword = 'New password should be different from your old one!';
  }

  const passwordValidationError = validatePassword(newPassword);

  if (passwordValidationError) {
    errors.newPassword = passwordValidationError;
  }

  if (newPassword !== confirmation) {
    errors.confirmation = 'Passwords do not match; please check and try again';
  }

  if (errors.confirmation || errors.oldPassword || errors.newPassword) {
    throw ApiError.badRequest('Validation error', errors);
  }

  await userService.updatePassword(foundUser, newPassword);

  res.status(200).send(getSuccessfulMessage(foundUser, 'password'));
};

const sendEmailConfirmation = async (req, res) => {
  const { id } = req.params;
  const { email, password } = req.body;
  const errors = {};

  if (!email || !password) {
    throw ApiError.badRequest(
      'You need to provide a new email and current password!'
    );
  }

  const foundUser = await userService.getUserById(id);

  checkUserExistence(foundUser, id);

  if (!(await bcrypt.compare(password, foundUser.password))) {
    errors.password = 'Incorrect password for changing email!';
  }

  if (email === foundUser.email) {
    errors.email = 'Your new email should be different from your current one!';
  }

  if (errors.password || errors.email) {
    throw ApiError.badRequest('Invalid input data!', errors);
  }

  await userService.sendEmailConfirmation(foundUser, email, res);

  res.status(200).send({
    message: `Confirm your new email please! You have been sent an email with confirmation!`,
  });
};

const updateEmail = async (req, res) => {
  const { confirmationToken } = req.params;

  if (!confirmationToken) {
    throw ApiError.badRequest('Missing confirmation token!');
  }

  const foundUser = await userService.updateEmail(confirmationToken);

  res.clearCookie('confirmationToken');

  res.status(200).send({
    message: 'Your email has been updated successfully!',
    updatedUser: foundUser,
  });
};

const authorizeWithGoogle = async (req, res) => {
  const { displayName, emails } = req.user;

  if (!displayName || !emails) {
    throw ApiError.badRequest(
      'Something went wrong! Try to authorize with google again'
    );
  }

  const newUser = await userService.googleCreateNewUser(
    emails[0].value,
    displayName
  );

  const accessToken = await prepareTokens(newUser, res);

  res.redirect(
    `${process.env.CLIENT_HOST}#google-auth/?message=Authenticated%20with%20google&id=${newUser.id}&name=${displayName}&email=${emails[0].value}&accessToken=${accessToken}`
  );
};

const logoutWithGoogle = async (req, res) => {
  const { userId } = req.params;

  await tokenService.remove(userId);

  req.session.destroy((err) => {
    if (err) {
      throw ApiError.unAuthorized('Error destroying session', { error: err });
    }
    res.redirect('/auth/google');
  });
};

const authController = {
  register,
  activate,
  login,
  sendAuthentication,
  logout,
  refresh,
  forgotPassword,
  resetPassword,
  updateEmail,
  updateName,
  updatePassword,
  sendEmailConfirmation,
  authorizeWithGoogle,
  logoutWithGoogle,
};

module.exports = { authController };
