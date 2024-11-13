import { Model } from "sequelize";

export default (sequelize, DataTypes) => {
  class RestaurantOperationalStatus extends Model {
    static associate(models) {
      RestaurantOperationalStatus.hasOne(models.Restaurant, {
        foreignKey: "operational_status_uuid",
        as: "restaurant",
      });
      RestaurantOperationalStatus.belongsTo(models.User, {
        foreignKey: "created_by",
        as: "creator",
      });
      RestaurantOperationalStatus.belongsTo(models.User, {
        foreignKey: "updated_by",
        as: "updater",
      });
    }
  }

  RestaurantOperationalStatus.init(
    {
      uuid: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      earnings_percentage: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: false,
      },
      membership_active: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
      admin_approved: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
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
      modelName: "RestaurantOperationalStatus",
      tableName: "restaurant_operational_statuses",
      timestamps: true,
      createdAt: "created_at",
      updatedAt: "updated_at",
      paranoid: true, // Enables soft delete
      deletedAt: "deleted_at",
    }
  );

  return RestaurantOperationalStatus;
};
