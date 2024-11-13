import { Model } from "sequelize";

export default (sequelize, DataTypes) => {
  class DeliveryPartnerDocument extends Model {
    static associate(models) {
      DeliveryPartnerDocument.hasOne(models.DeliveryPartner, {
        foreignKey: "delivery_partner_document_uuid",
        as: "deliveryPartner",
      });
      DeliveryPartnerDocument.belongsTo(models.User, {
        foreignKey: "created_by",
        as: "creator",
      });
      DeliveryPartnerDocument.belongsTo(models.User, {
        foreignKey: "updated_by",
        as: "updater",
      });
    }
  }

  DeliveryPartnerDocument.init(
    {
      uuid: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
      },
      license_number: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      license: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      license_expiry_date: {
        type: DataTypes.DATEONLY,
        allowNull: false,
        set(value) {
          const [day, month, year] = value.split("-");
          this.setDataValue("license_expiry_date", `${year}-${month}-${day}`);
        },
      },
      vehicle_number: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      vehicle_type: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      document_type: {
        type: DataTypes.ENUM("PAN Number", "Aadhar Number"),
        allowNull: false,
      },
      document_number: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      document: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      created_by: {
        type: DataTypes.UUID,
        allowNull: true,
        references: {
          model: "users",
          key: "uuid",
        },
      },
      updated_by: {
        type: DataTypes.UUID,
        allowNull: true,
        references: {
          model: "users",
          key: "uuid",
        },
      },
    },
    {
      sequelize,
      modelName: "DeliveryPartnerDocument",
      tableName: "delivery_partner_documents",
      timestamps: true, // Automatically handle created_at and updated_at
      createdAt: "created_at", // Custom name for createdAt
      updatedAt: "updated_at", // Custom name for updatedAt
      paranoid: true, // Enable soft deletes
      deletedAt: "deleted_at", // Custom name for deletedAt
    }
  );

  return DeliveryPartnerDocument;
};
