import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"; // For password hashing
import {
  createUserRole,
  findRoleByName,
  findUserByEmail,
  findUserByEmailOrPhoneNumber,
  createUser,
  findUserRoles,
  createRestaurant,
  createDeliveryPartner,
  saveRefreshToken,
  findUserByEmailRole,
  deleteRefreshToken,
} from "./authRepository.js";
import ApiError from "../../utils/apiError.js";
import databaseConfig from "../../models/index.js";
import { sendMail } from "../../utils/sendMail.js";

const { sequelize } = databaseConfig.db;

const register = async (registrationDetails) => {
  const transaction = await sequelize.transaction();
  const {
    first_name,
    last_name,
    email,
    decoded_password,
    country_code,
    phone_number,
    date_of_birth,
    role_name,
    other_details,
  } = registrationDetails;

  try {
    let user = await findUserByEmailOrPhoneNumber(
      email,
      phone_number,
      transaction
    );

    const role = await findRoleByName(role_name, transaction);

    if (user) {
      const roleExists = user.roles.includes(role_name);

      if (roleExists) {
        throw new ApiError(
          "User with given email or phone number already exists",
          400
        );
      } else {
        if (role_name === "restaurant") {
          await createRestaurant(user.uuid, other_details, transaction);
        } else if (role_name === "delivery_partner") {
          await createDeliveryPartner(user.uuid, other_details, transaction);
        }
        await createUserRole(user.uuid, role.uuid, transaction);
        await transaction.commit();
        throw new ApiError(
          `You are already registered with us as ${user.roles[0].name}. Use the same set of credentials to login as ${role_name}`,
          400
        );
      }
    } else {
      user = await createUser(
        {
          first_name,
          last_name,
          email,
          password: decoded_password,
          country_code,
          phone_number,
          date_of_birth,
        },
        transaction
      );
      if (role_name === "restaurant") {
        await createRestaurant(user.uuid, other_details, transaction);
      } else if (role_name === "delivery_partner") {
        await createDeliveryPartner(user.uuid, other_details, transaction);
      }
      await createUserRole(user.uuid, role.uuid, transaction);
      await transaction.commit();
      return {
        message: "You are registered successfully",
      };
    }
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

const checkUserExistence = async (email) => {
  const transaction = await sequelize.transaction();
  try {
    const user = await findUserByEmailOrPhoneNumber(email, "", transaction);

    if (user) {
      return user;
    } else {
      throw new ApiError(
        "User with given email does not exist. Register Instead.",
        400
      );
    }
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

const loginWithGoogle = async (user, role) => {
  const { email, first_name, last_name } = user;

  role = role.toLowerCase();

  // check if user already exists or not.
  let userDetails = await findUserByEmailRole(email);

  // user with role customer is trying to sign up or log in
  if (!role || role.toLowerCase() === "customer") {
    // get role_uuid for customer role
    const customer_role = await findRoleByName("customer");

    // user already exists, check role and then allow signup
    if (userDetails) {
      const roleExists = userDetails.roles.find(
        (userRole) => userRole.name === "customer"
      );

      let roleNames;
      // if role exists then directly log in
      if (!roleExists) {
        await createUserRole(userDetails.uuid, customer_role.uuid);
        roleNames = ["customer"];
      }
      roleNames =
        roleNames || userDetails.roles.map((userRole) => userRole.name);

      const { accessToken, refreshToken } =
        await generateAccessAndRefreshTokens(
          userDetails.uuid,
          customer_role.uuid
        );

      return {
        user: {
          first_name: userDetails.first_name,
          last_name: userDetails.last_name,
          email: userDetails.email,
        },
        roleNames,
        accessToken,
        refreshToken,
      };
    } else {
      // create a new user as well as user role and then generate tokens
      const transaction = await sequelize.transaction();
      try {
        // create user
        userDetails = await createUser(
          { email, first_name, last_name },
          transaction
        );

        // assign customer role to user
        await createUserRole(userDetails.uuid, customer_role.uuid, transaction);

        // commit given transaction
        await transaction.commit();

        // login successful
        const { accessToken, refreshToken } =
          await generateAccessAndRefreshTokens(
            userDetails.uuid,
            customer_role.uuid
          );

        return {
          user: {
            first_name: userDetails.first_name,
            last_name: userDetails.last_name,
            email: userDetails.email,
          },
          roleNames: ["customer"],
          accessToken,
          refreshToken,
        };
      } catch (error) {
        await transaction.rollback();
        throw new ApiError("Internal Server Error", 500);
      }
    }
  }
  // try to login user with either delivery partner or restaurant role
  else {
    if (!userDetails) {
      throw new ApiError(
        "User not found. Please sign up to create an account.",
        404
      );
    } else {
      // const userRoles = await findUserRoles(userDetails.uuid);
      let roleNames = userDetails.roles.map((userRole) => userRole.name);

      let roleExists = userDetails.roles.find(
        (userRole) => userRole.name === role
      );

      if (!roleExists) {
        throw new ApiError(
          "User not found. Please sign up to create an account.",
          404
        );
      } else {
        let currentRoleId = userDetails.roles.find(
          (userRole) => userRole.name === role
        ).uuid;
        // generate tokens and login user
        const { accessToken, refreshToken } =
          await generateAccessAndRefreshTokens(userDetails.uuid, currentRoleId);
        return {
          user: {
            first_name: userDetails.first_name,
            last_name: userDetails.last_name,
            email: userDetails.email,
          },
          roleNames,
          accessToken,
          refreshToken,
        };
      }
    }
  }
};

const loginUser = async ({ email, password, role }) => {
  // Decode the password
  password = decodeURIComponent(atob(password));

  // Find the user by email and include associated roles
  const user = await findUserByEmailRole(email);

  // send error in case user not found or role doesn't exist
  if (!user) {
    throw new ApiError("User not found", 404);
  }

  // Extract the role UUIDs from the associated roles
  const roleNames = user.roles.map((role) => role.name);

  if (!roleNames.includes(role)) {
    throw new ApiError(
      `It looks like you're already signed up with us as a ${roleNames[0]}. Please also sign up as a ${role} to proceed.`,
      401
    );
  }

  // Check if user logged in via google and no password exists
  if (!user.password) {
    throw new ApiError(
      "It looks like you signed up with Google. Please log in using the Google option, as no password is set for this account.",
      403
    );
  }

  // Validate password
  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw new ApiError(
      "Invalid credentials. Please check your email and password and try again",
      401
    );
  }

  const currentRoleId = user.roles.find((roles) => roles.name === role).uuid;

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user.uuid,
    currentRoleId
  );

  return {
    user: {
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
    },
    roleNames,
    accessToken,
    refreshToken,
  };
};

// Function to handle user logout
const logoutUser = async (refreshToken) => {
  // delete refresh token
  await deleteRefreshToken(refreshToken);
};

// Function to generate access token (short-lived)
const generateAccessToken = (userId, currentRoleId) => {
  return jwt.sign(
    {
      // Include both userId and roleIds in the token payload
      userId,
      currentRoleId,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN }
  );
};

// Function to generate refresh token (long-lived)
const generateRefreshToken = async (userId, currentRoleId) => {
  const refreshToken = jwt.sign(
    {
      // Include both userId and roleIds in the token payload
      userId,
      currentRoleId,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );
  await saveRefreshToken(userId, refreshToken);
  return refreshToken;
};

// Function to generate both access and refresh tokens
const generateAccessAndRefreshTokens = async (userId, currentRoleId) => {
  const accessToken = generateAccessToken(userId, currentRoleId);
  const refreshToken = await generateRefreshToken(userId, currentRoleId);

  return { accessToken, refreshToken };
};

const forgotPasswordService = async (protocol, email) => {
  const transaction = await sequelize.transaction();
  try {
    const user = await findUserByEmail(email);

    if (user) {
      const passwordResetToken = await user.createPasswordResetToken();

      // Replace the domain and port according to the frontend
      const resetURL = `${protocol}://${process.env.FRONTEND_HOST}:${process.env.FRONTEND_PORT}/reset-password/${passwordResetToken}`;

      const message = `<p>We have received a request to reset your password. Please use the below link to reset your password:</p>
        <p><a href="${resetURL}">Reset Password</a></p>
        <p>This reset password link will expire in 15 minutes.</p>`;

      try {
        await sendMail({
          email: user.email,
          subject: "Password Reset",
          message,
        });
      } catch (error) {
        user.password_reset_token = undefined;
        user.password_reset_token_expiry = undefined;
        await user.save({
          validateBeforeSave: false,
        });

        throw new ApiError(
          "There was an error sending password reset email. Please try again later!",
          500
        );
      }
      return {
        message: `Password reset link has been sent to ${email}`,
      };
    } else {
      throw new ApiError(
        "User with given email does not exist. Register Instead.",
        400
      );
    }
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};
const resetPasswordService = async (token, newPassword) => {
  const transaction = await sequelize.transaction();
  try {
    // Hash the token to match it with the stored token
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // Find the user with the hashed token and check if the token has not expired
    const user = await User.findOne({
      where: {
        password_reset_token: hashedToken,
        password_reset_token_expiry: {
          [Op.gt]: new Date(),
        },
      },
    });

    if (!user) {
      throw new ApiError("Token is invalid or has expired", 400);
    }

    // Update the password and remove reset token and expiry
    user.password = await hashPassword(newPassword); // Ensure password is hashed
    user.password_reset_token = null;
    user.password_reset_token_expiry = null;
    await user.save({ transaction });

    await transaction.commit();

    return {
      message: "Password reset successfully",
    };
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

export {
  register,
  checkUserExistence,
  loginUser,
  logoutUser,
  loginWithGoogle,
  generateAccessToken,
  generateAccessAndRefreshTokens,
  forgotPasswordService,
};
