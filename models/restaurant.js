import { Model } from "sequelize";

export default (sequelize, DataTypes) => {
  class Restaurant extends Model {
    static associate(models) {
      Restaurant.belongsTo(models.User, {
        foreignKey: "owner_uuid",
        as: "owner",
      });
      Restaurant.belongsTo(models.RestaurantOperationalStatus, {
        foreignKey: "operational_status_uuid",
        as: "operationalStatus",
      });
      Restaurant.belongsTo(models.RestaurantDocument, {
        foreignKey: "restaurant_document_uuid",
        as: "restaurantDocument",
      });
      Restaurant.hasOne(models.Address, {
        foreignKey: "restaurant_uuid",
        as: "address",
      });
      Restaurant.belongsTo(models.User, {
        foreignKey: "created_by",
        as: "creator",
      });
      Restaurant.belongsTo(models.User, {
        foreignKey: "updated_by",
        as: "updater",
      });
    }
  }

  Restaurant.init(
    {
      uuid: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      owner_uuid: {
        type: DataTypes.UUID,
        references: {
          model: "users",
          key: "uuid",
        },
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      images: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        allowNull: true,
      },
      is_pure_veg: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      avg_rating: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: true,
      },
      operating_hour: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
      is_open: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true,
      },
      is_valid: {
        type: DataTypes.BOOLEAN,
        allowNull: true,
      },
      temporarily_closed: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
      operational_status_uuid: {
        type: DataTypes.UUID,
        references: {
          model: "restaurant_operational_statuses",
          key: "uuid",
        },
      },
      restaurant_document_uuid: {
        type: DataTypes.UUID,
        references: {
          model: "restaurant_documents",
          key: "uuid",
        },
      },
      created_by: {
        type: DataTypes.UUID,
        references: {
          model: "users", // Name of the User table
          key: "uuid", // Primary key in the User table
        },
      },
      updated_by: {
        type: DataTypes.UUID,
        references: {
          model: "users", // Name of the User table
          key: "uuid", // Primary key in the User table
        },
      },
    },
    {
      sequelize,
      modelName: "Restaurant",
      tableName: "restaurants",
      timestamps: true,
      createdAt: "created_at",
      updatedAt: "updated_at",
      paranoid: true, // Enables soft delete
      deletedAt: "deleted_at",
    }
  );

  return Restaurant;
};
