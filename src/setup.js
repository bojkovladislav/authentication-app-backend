'use strict';

const { sequelize } = require('./utils/db.js');

sequelize.sync();

sequelize
  .authenticate()
  .then(() => {
    console.log('Connection has been established successfully.');
  })
  .catch((err) => {
    console.error('Unable to connect to the database:', err);
  });
