"use strict";

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable("users", {
      uuid: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      first_name: {
        type: Sequelize.STRING(50), // Length constraint
        allowNull: false, // Cannot be null
      },
      last_name: {
        type: Sequelize.STRING(50), // Max length of 50 characters
        allowNull: true, // Can be null
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
      },
      country_code: {
        type: Sequelize.STRING,
        allowNull: true,
        validate: {
          is: /^\+\d{1,4}$/, // Validates that country code starts with + and has 1-4 digits
        },
      },
      phone_number: {
        type: Sequelize.STRING,
        unique: true,
        allowNull: true,
        validate: {
          is: /^[0-9]{7,15}$/, // Only numbers, 7 to 15 digits for the local part
        },
      },
      password: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      date_of_birth: {
        type: Sequelize.DATEONLY,
      },
      password_reset_token: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      password_reset_token_expiry: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      password_updated_at: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      deleted_at: {
        type: Sequelize.DATE,
        allowNull: true,
      },
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable("users");
  },
};
