import { Model } from "sequelize";

export default (sequelize, DataTypes) => {
  class Address extends Model {
    static associate(models) {
      Address.belongsTo(models.User, {
        foreignKey: "user_uuid",
        as: "user",
      });
      Address.belongsTo(models.Restaurant, {
        foreignKey: "restaurant_uuid",
        as: "restaurant",
      });
      Address.belongsTo(models.User, {
        foreignKey: "created_by",
        as: "creator",
      });
      Address.belongsTo(models.User, {
        foreignKey: "updated_by",
        as: "updater",
      });
    }
  }

  Address.init(
    {
      uuid: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      user_uuid: {
        type: DataTypes.UUID,
        references: {
          model: "users",
          key: "uuid",
        },
      },
      restaurant_uuid: {
        type: DataTypes.UUID,
        references: {
          model: "restaurants",
          key: "uuid",
        },
      },
      entity_type: {
        type: DataTypes.ENUM,
        values: ["user", "restaurant"],
        allowNull: false,
      },
      house_no: {
        type: DataTypes.STRING,
      },
      lane_1: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      lane_2: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      landmark: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      pincode: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isNumeric: true, // Ensures only numeric values
          len: {
            args: [6, 6], // Pincode must be exactly 6 digits long
            msg: "Pincode must be exactly 6 digits long for India",
          },
        },
      },
      city: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      state: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      country: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      address_type: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      latitude: {
        type: DataTypes.DECIMAL(10, 8),
      },
      longitude: {
        type: DataTypes.DECIMAL(11, 8),
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
      deleted_at: {
        type: DataTypes.DATE,
      },
    },
    {
      sequelize,
      modelName: "Address",
      tableName: "addresses",
      timestamps: true,
      createdAt: "created_at", // Custom name for createdAt
      updatedAt: "updated_at", // Custom name for updatedAt
      paranoid: true, // enables soft deletion with deletedAt
      deletedAt: "deleted_at", // custom name for deletedAt
    }
  );

  return Address;
};
