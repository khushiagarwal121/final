import databaseConfig from "../../models/index.js";
import { Op } from "sequelize";

const {
  User,
  Role,
  UserRole,
  RefreshToken,
  Address,
  Restaurant,
  RestaurantDocument,
  DeliveryPartner,
  DeliveryPartnerDocument,
} = databaseConfig.db;

const findUserByEmail = async (email) => {
  return await User.findOne({ where: { email } });
};

const findUserRoles = async (user_uuid) => {
  return await UserRole.findAll({ where: { user_uuid } });
};

const createUserRole = async (user_uuid, role_uuid, transaction) => {
  return await UserRole.create(
    {
      user_uuid,
      role_uuid,
    },
    {
      transaction,
    }
  );
};

const findRoleByName = async (roleName, transaction) => {
  return await Role.findOne(
    {
      where: { name: roleName },
    },
    {
      transaction,
    }
  );
};

const createUser = async (userDetails, transaction) => {
  return await User.create(
    {
      ...userDetails,
    },
    {
      transaction,
    }
  );
};

const findUserByEmailOrPhoneNumber = async (
  email,
  phone_number,
  transaction
) => {
  const user = await User.findOne(
    {
      where: {
        [Op.or]: [{ phone_number }, { email }],
      },
      include: [
        {
          model: Role, // Reference to the Role model
          through: { attributes: [] }, // Exclude fields from the through table i.e UserRole
          attributes: ["name"], // Select only the role name
          as: "roles",
        },
      ],
    },
    {
      transaction,
    }
  );

  if (user) {
    // Map roles to get an array of role names
    user.roles = user.roles.map((role) => role.name);
  }

  return user;
};

const createRestaurant = async (owner_uuid, other_details, transaction) => {
  const {
    name,
    images,
    is_pure_veg,
    operating_hour,
    fssai_number,
    fssai_valid_from,
    fssai_valid_to,
    fssai_certificate,
    gst_number,
    gst_certificate,
    pan_number,
    house_no,
    lane_1,
    lane_2,
    landmark,
    pincode,
    city,
    state,
    country,
    latitude,
    longitude,
  } = other_details;

  const restaurantDocument = await RestaurantDocument.create(
    {
      fssai_number,
      fssai_valid_from,
      fssai_valid_to,
      fssai_certificate,
      gst_number,
      gst_certificate,
      pan_number,
      created_by: owner_uuid,
      updated_by: owner_uuid,
    },
    { transaction }
  );

  // Create Restaurant with associated RestaurantDocument
  const restaurant = await Restaurant.create(
    {
      owner_uuid,
      name,
      images,
      is_pure_veg,
      operating_hour,
      restaurant_document_uuid: restaurantDocument.uuid,
      created_by: owner_uuid,
      updated_by: owner_uuid,
    },
    {
      transaction,
    }
  );

  await Address.create(
    {
      restaurant_uuid: restaurant.uuid, // reference to Restaurant
      entity_type: "restaurant",
      house_no,
      lane_1,
      lane_2,
      landmark,
      pincode,
      city,
      state,
      country,
      latitude,
      longitude,
      created_by: owner_uuid,
      updated_by: owner_uuid,
    },
    { transaction }
  );

  return restaurant;
};

const createDeliveryPartner = async (user_uuid, other_details, transaction) => {
  const {
    profile_image,
    city,
    license_number,
    license,
    license_expiry_date,
    vehicle_number,
    vehicle_type,
    document_type,
    document_number,
    document,
  } = other_details;

  const deliveryPartnerDocument = await DeliveryPartnerDocument.create(
    {
      license_number,
      license,
      license_expiry_date, // MM/YY format will be handled by the setter
      vehicle_number,
      vehicle_type,
      document_type,
      document_number,
      document,
      created_by: user_uuid,
      updated_by: user_uuid,
    },
    { transaction }
  );

  const deliveryPartner = await DeliveryPartner.create(
    {
      user_uuid,
      profile_image,
      city,
      created_by: user_uuid,
      updated_by: user_uuid,
      delivery_partner_document_uuid: deliveryPartnerDocument.uuid,
    },
    { transaction }
  );

  return deliveryPartner;
};

const findUserByEmailRole = async (email) => {
  return User.findOne({
    where: { email },
    include: [
      {
        model: Role,
        as: "roles",
        attributes: ["uuid", "name"], // Only fetch the UUID and name of each role
      },
    ],
  });
};

const saveRefreshToken = async (userUuid, token) => {
  const expirationDuration = process.env.REFRESH_TOKEN_EXPIRES_IN || "7";
  const days = parseInt(expirationDuration, 10);
  const expirationDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  let refreshToken = await RefreshToken.findOne({
    where: {
      user_uuid: userUuid,
    },
  });

  if (refreshToken) {
    // Update the existing token
    await refreshToken.update({
      token,
      expires_at: expirationDate,
    });
  } else {
    // Create a new refresh token
    refreshToken = await RefreshToken.create({
      user_uuid: userUuid,
      token,
      expires_at: expirationDate,
    });
  }
  return refreshToken;
};

const deleteRefreshToken = async (refreshToken) => {
  return RefreshToken.destroy({
    where: { token: refreshToken },
  });
};

// Export repository functions
export {
  findUserByEmail,
  findUserByEmailRole,
  findUserRoles,
  findRoleByName,
  createUserRole,
  createUser,
  saveRefreshToken,
  findUserByEmailOrPhoneNumber,
  createRestaurant,
  createDeliveryPartner,
  deleteRefreshToken,
};
