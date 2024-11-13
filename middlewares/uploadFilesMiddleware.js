import { respondError } from "../utils/responseHandler.js";
import ApiError from "../utils/apiError.js";
import upload from "./multerConfig.js";
import multer from "multer";

const uploadFilesMiddleware = (req, res, next) => {
  upload.fields([
    { name: "fssai_certificate", maxCount: 1 },
    { name: "gst_certificate", maxCount: 1 },
    { name: "images", maxCount: 1 },
    { name: "profile_image", maxCount: 1 },
    { name: "license", maxCount: 1 },
    { name: "document", maxCount: 1 },
  ])(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError || err instanceof ApiError) {
        respondError(res, {
          message: err.message,
          statusCode: 400,
        });
      } else {
        respondError(res, {
          message: "An error occurred during file upload.",
          statusCode: 500,
        });
      }
    }
    next();
  });
};

export default uploadFilesMiddleware;
