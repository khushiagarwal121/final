"use strict";

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable("user_roles", {
      uuid: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      user_uuid: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: "users", // The name of the users table
          key: "uuid", // The primary key in the users table
        },
      },
      role_uuid: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: "roles", // The name of the roles table
          key: "uuid", // The primary key in the roles table
        },
      },
      created_by: {
        type: Sequelize.UUID,
        references: {
          model: "users", // The name of the users table
          key: "uuid", // The primary key in the users table
        },
      },
      updated_by: {
        type: Sequelize.UUID,
        references: {
          model: "users", // The name of the users table
          key: "uuid", // The primary key in the users table
        },
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

    await queryInterface.addConstraint("user_roles", {
      fields: ["user_uuid", "role_uuid"],
      type: "unique",
      name: "unique_user_role", // Custom name for the unique constraint
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable("user_roles");
  },
};
