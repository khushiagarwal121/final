import { Sequelize, DataTypes } from "sequelize";
import User from "./user.js";
import Role from "./role.js";
import UserRole from "./user_role.js";
import RefreshToken from "./refresh_token.js";
import Address from "./address.js";
import Restaurant from "./restaurant.js";
import RestaurantOperationalStatus from "./restaurant_operational_status.js";
import DeliveryPartnerDocument from "./delivery_partner_document.js";
import RestaurantDocument from "./restaurant_document.js";
import DeliveryPartner from "./delivery_partner.js";

// connect to local database
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: "postgres",
    logging: false,
  }
);

const db = {
  Sequelize,
  sequelize,
};

db.User = User(sequelize, DataTypes);
db.Role = Role(sequelize, DataTypes);
db.UserRole = UserRole(sequelize, DataTypes);
db.RefreshToken = RefreshToken(sequelize, DataTypes);
db.Address = Address(sequelize, DataTypes);
db.Restaurant = Restaurant(sequelize, DataTypes);
db.RestaurantOperationalStatus = RestaurantOperationalStatus(
  sequelize,
  DataTypes
);
db.RestaurantDocument = RestaurantDocument(sequelize, DataTypes);
db.DeliveryPartnerDocument = DeliveryPartnerDocument(sequelize, DataTypes);
db.DeliveryPartner = DeliveryPartner(sequelize, DataTypes);

db.User.associate(db);
db.Role.associate(db);
db.Address.associate(db);
db.RefreshToken.associate(db);
db.RestaurantOperationalStatus.associate(db);
db.Restaurant.associate(db);
db.RestaurantDocument.associate(db);
db.DeliveryPartner.associate(db);
db.DeliveryPartnerDocument.associate(db);

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log("Connection has been established successfully.");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }
};

export default { db, connectDB };
