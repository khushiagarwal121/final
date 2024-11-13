import { Model } from "sequelize";
import bcrypt from "bcrypt";
import crypto from "crypto";

export default (sequelize, DataTypes) => {
  class User extends Model {
    static associate(models) {
      User.belongsToMany(models.Role, {
        through: models.UserRole,
        foreignKey: "user_uuid", // Foreign key in UserRole
        otherKey: "role_uuid", // Other key in UserRole
        as: "roles",
      });
      User.hasMany(models.Address, {
        foreignKey: "user_uuid", // Foreign key in Address table
        as: "addresses", // Alias for the relationship
      });
      User.hasMany(models.Restaurant, {
        foreignKey: "owner_uuid", // Foreign key in Restaurant table
        as: "restaurants", // Alias for the relationship
      });
    }

    async createPasswordResetToken() {
      const resetToken = crypto.randomBytes(32).toString("hex");

      this.password_reset_token = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

      this.password_reset_token_expiry = new Date(
        Date.now() + Number(process.env.PASSWORD_RESET_TOKEN_EXPIRY)
      );

      await this.save();

      return resetToken;
    }
  }

  User.init(
    {
      uuid: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      first_name: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          notEmpty: {
            msg: "First name cannot be empty.",
          },
          isAlpha: {
            msg: "First name should contain only letters.",
          },
          len: {
            args: [3, 50],
            msg: "First name must be between 3 and 50 characters.",
          },
        },
      },
      last_name: {
        type: DataTypes.STRING,
        allowNull: true,
        validate: {
          isAlpha: {
            msg: "Last name should contain only letters.",
          },
          len: {
            args: [2, 50],
            msg: "Last name must be between 2 to 50 characters.",
          },
        },
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          notEmpty: {
            msg: "Email is required.",
          },
          isEmail: {
            msg: "Email must be a valid email address.",
          },
        },
      },
      country_code: {
        type: DataTypes.STRING,
        allowNull: true,
        validate: {
          is: /^\+\d{1,4}$/, // Validates that country code starts with + and has 1-4 digits
        },
      },
      phone_number: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: true,
        validate: {
          is: /^[0-9]{7,15}$/, // Only numbers, 7 to 15 digits for the local part
        },
      },
      password: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      date_of_birth: {
        type: DataTypes.DATEONLY,
      },
      password_reset_token: {
        type: DataTypes.STRING,
        allowNull: true, // Allow null for users without a reset token
      },
      password_reset_token_expiry: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      password_updated_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      modelName: "User",
      tableName: "users",
      timestamps: true, // Automatically adds createdAt and updatedAt
      createdAt: "created_at", // Custom name for createdAt
      updatedAt: "updated_at", // Custom name for updatedAt
      paranoid: true, // enables soft deletion with deletedAt
      deletedAt: "deleted_at", // custom name for deletedAt
      hooks: {
        beforeCreate: async (user) => {
          if (user.password && !user._previousDataValues.password) {
            user.password = await bcrypt.hash(user.password, 10);
          }
        },
      },
    }
  );

  return User;
};
