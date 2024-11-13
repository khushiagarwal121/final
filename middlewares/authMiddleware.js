import jwt from "jsonwebtoken";
import { generateAccessToken } from "../features/auth/authService.js";
import ApiError from "../utils/apiError.js";
import { respondOk, respondError } from "../utils/responseHandler.js";

const authenticate = async (req, res, next) => {
  try {
    let { refreshToken, accessToken } = req.cookies;

    if (!accessToken) {
      if (!refreshToken) {
        throw new ApiError("Access and refresh tokens are missing.", 401);
      }

      // decode the refresh token
      const decodedRefreshToken = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      const { userId, currentRoleId } = decodedRefreshToken;

      // refreshing access token
      accessToken = generateAccessToken(userId, currentRoleId);

      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        maxAge: process.env.ACCESS_TOKEN_EXPIRY_COOKIE,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: process.env.REFRESH_TOKEN_EXPIRY_COOKIE,
      });

      req.user_uuid = userId;
      req.current_role_uuid = currentRoleId;
      return next();
    } else {
      const { userId, currentRoleId } = jwt.verify(
        accessToken,
        process.env.ACCESS_TOKEN_SECRET
      );
      req.user_uuid = userId;
      req.current_role_uuid = currentRoleId;
      return next();
    }
  } catch (error) {
    !(error instanceof ApiError) &&
      (error.statusCode = 500) &&
      (error.message =
        "Internal Server Error: Something went wrong, Please try again later");
    respondError(res, {
      message: error.message,
      statusCode: error.statusCode,
    });
  }
};

export { authenticate };
