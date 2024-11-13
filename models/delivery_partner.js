import { DataTypes, Model } from "sequelize";

export default (sequelize) => {
  class DeliveryPartner extends Model {
    static associate(models) {
      DeliveryPartner.belongsTo(models.User, {
        foreignKey: "user_uuid",
        as: "user",
      });
      DeliveryPartner.belongsTo(models.DeliveryPartnerDocument, {
        foreignKey: "delivery_partner_document_uuid",
        as: "deliveryPartnerDocument",
      });
      DeliveryPartner.belongsTo(models.User, {
        foreignKey: "created_by",
        as: "creator",
      });
      DeliveryPartner.belongsTo(models.User, {
        foreignKey: "updated_by",
        as: "updater",
      });
    }
  }

  // Initialize the model
  DeliveryPartner.init(
    {
      uuid: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      user_uuid: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
          model: "users",
          key: "uuid",
        },
      },
      average_rating: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: true,
      },
      profile_image: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      status: {
        type: DataTypes.ENUM("on_delivery", "off_duty", "available"),
        allowNull: false,
      },
      city: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      is_approved: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
      approval_time: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      delivery_partner_document_uuid: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
          model: "delivery_partner_documents",
          key: "uuid",
        },
      },
      created_by: {
        type: DataTypes.UUID,
        references: {
          model: "users",
          key: "uuid",
        },
      },
      updated_by: {
        type: DataTypes.UUID,
        references: {
          model: "users",
          key: "uuid",
        },
      },
    },
    {
      sequelize, // Pass the Sequelize instance
      modelName: "DeliveryPartner", //Name of the model
      tableName: "delivery_partners", // Name of the table in the database
      timestamps: true, // Automatically handle created_at and updated_at
      paranoid: true, // Enable soft deletes
      createdAt: "created_at", // Set custom column names if needed
      updatedAt: "updated_at", // Set custom column names if needed
      deletedAt: "deleted_at", // Custom name for deletedAt
    }
  );

  return DeliveryPartner;
};
