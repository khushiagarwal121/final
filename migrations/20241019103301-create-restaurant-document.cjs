"use strict";

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable("restaurant_documents", {
      uuid: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
      },
      fssai_number: {
        type: Sequelize.STRING(14),
        allowNull: false,
        validate: {
          len: {
            args: [14, 14], // Ensure it's exactly 14 characters long
            msg: "FSSAI number must be 14 characters long",
          },
        },
      },
      fssai_valid_from: {
        type: Sequelize.DATEONLY,
        allowNull: false,
      },
      fssai_valid_to: {
        type: Sequelize.DATEONLY,
        allowNull: false,
      },
      fssai_certificate: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      gst_number: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      gst_certificate: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      pan_number: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      created_by: {
        type: Sequelize.UUID,
        allowNull: true,
        references: {
          model: "users",
          key: "uuid",
        },
      },
      updated_by: {
        type: Sequelize.UUID,
        allowNull: true,
        references: {
          model: "users",
          key: "uuid",
        },
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
    await queryInterface.dropTable("restaurant_documents");
  },
};
