import { respondError } from "../utils/responseHandler.js";

const validateRequest = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body);

  if (error) {
    // validation fails
    return respondError(res, {
      statusCode: 400,
      message:
        `Bad Request: ${error.details[0].message}` ||
        "Invalid request body. Please check the input and try again.",
    });
  }

  // validation success
  next();
};

export { validateRequest };
