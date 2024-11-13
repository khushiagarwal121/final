import Joi from "joi";

const restaurantSchema = Joi.object({
  name: Joi.string().required().messages({
    "string.base": "Name must be a string.",
    "any.required": "Name is required.",
  }),
  images: Joi.array().items(Joi.string()).optional(),
  is_pure_veg: Joi.boolean().required().messages({
    "boolean.base": "is_pure_veg must be a boolean.",
    "any.required": "Please select whether your restaurant is pure veg or not.",
  }),
  operating_hour: Joi.object()
    .pattern(
      Joi.string().valid(
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday"
      ),
      Joi.array()
        .max(2)
        .items(
          Joi.object({
            start_time: Joi.string()
              .pattern(/^(0[1-9]|1[0-2]):[0-5][0-9] (AM|PM)$/)
              .required()
              .messages({
                "string.pattern.base":
                  "Start time must be in 'HH:MM AM/PM' format.",
                "any.required": "Start time is required.",
              }),
            end_time: Joi.string()
              .pattern(/^(0[1-9]|1[0-2]):[0-5][0-9] (AM|PM)$/)
              .required()
              .custom((value, helpers) => {
                const [start, end] = [
                  helpers.state.ancestors[0].start_time,
                  value,
                ];
                const startDate = new Date(`1970-01-01 ${start}`);
                const endDate = new Date(`1970-01-01 ${end}`);
                if (endDate <= startDate) {
                  return helpers.message("End time must be after start time.");
                }
                return value;
              })
              .messages({
                "string.pattern.base":
                  "End time must be in 'HH:MM AM/PM' format.",
                "any.required": "End time is required.",
              }),
          })
        )
    )
    .required()
    .messages({
      "object.base":
        "Operating hour must be a valid object with day-specific time slots.",
      "any.required": "Operating hour is required.",
    }),
  fssai_number: Joi.string().length(14).pattern(/^\d+$/).required().messages({
    "string.length": "FSSAI number must be exactly 14 characters long.",
    "string.pattern.base": "FSSAI number must contain only digits.",
    "any.required": "FSSAI number is required.",
  }),
  fssai_valid_from: Joi.date().required().messages({
    "date.base": "fssai_valid_from must be a valid date.",
    "any.required": "fssai_valid_from is required.",
  }),
  fssai_valid_to: Joi.date()
    .greater(Joi.ref("fssai_valid_from"))
    .required()
    .messages({
      "date.base": "fssai_valid_to must be a valid date.",
      "any.required": "fssai_valid_to is required.",
      "date.greater": "fssai_valid_to must be later than fssai_valid_from.",
    }),
  gst_number: Joi.string().required().messages({
    "string.base": "GST number must be a string.",
    "any.required": "GST number is required.",
  }),
  pan_number: Joi.string()
    .length(10) // Ensure length is 10
    .pattern(/^[A-Z]{5}\d{4}[A-Z]$/) // Validate the format
    .required()
    .messages({
      "string.base": "PAN number must be a string.",
      "string.length": "PAN number must be exactly 10 characters long.",
      "string.pattern.base": "PAN number is wrong.",
      "any.required": "PAN number is required.",
    }),
  house_no: Joi.string().optional().messages({
    "string.base": "house_no must be a string.",
  }),
  lane_1: Joi.string().required().messages({
    "string.base": "lane_1 must be a string.",
    "any.required": "lane_1 is required.",
  }),
  lane_2: Joi.string().optional().messages({
    "string.base": "lane_2 must be a string.",
  }),
  landmark: Joi.string().optional().messages({
    "string.base": "landmark must be a string.",
  }),
  pincode: Joi.string()
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      "string.pattern.base": "Pincode must be exactly 6 digits long for India.",
      "any.required": "Pincode is required.",
    }),
  city: Joi.string().required().messages({
    "string.base": "City must be a string.",
    "any.required": "City is required.",
  }),
  state: Joi.string().required().messages({
    "string.base": "State must be a string.",
    "any.required": "State is required.",
  }),
  country: Joi.string().required().messages({
    "string.base": "Country must be a string.",
    "any.required": "Country is required.",
  }),
  latitude: Joi.number().precision(8).optional().messages({
    "number.base": "Latitude must be a decimal number.",
  }),
  longitude: Joi.number().precision(8).optional().messages({
    "number.base": "Longitude must be a decimal number.",
  }),
});

const deliveryPartnerSchema = Joi.object({
  city: Joi.string().optional(),
  license_number: Joi.string()
    .length(15) // Ensure length is exactly 15
    .pattern(/^[A-Z]{2}\d{13}$/) // Validate the format (2 alphabets followed by 13 digits)
    .required()
    .messages({
      "string.base": "License number must be a string.",
      "string.length": "License number must be exactly 15 characters long.",
      "string.pattern.base": "License number is wrong.",
      "any.required": "License number is required.",
    }),
  license_expiry_date: Joi.string()
    .pattern(/^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-(\d{4})$/) // Validate DD-MM-YYYY format
    .required()
    .custom((value, helpers) => {
      const [day, month, year] = value.split("-").map(Number);
      const currentDate = new Date();
      const expiryDate = new Date(year, month - 1, day);

      // Validate that the date is not in the past
      if (expiryDate < currentDate) {
        return helpers.message(
          "Your license is expired. Please renew it first."
        );
      }

      return value;
    })
    .messages({
      "string.pattern.base":
        "License expiry date must be in DD-MM-YYYY format.",
      "any.required": "License expiry date is required.",
    }),
  vehicle_number: Joi.string()
    .length(10)
    .pattern(/^[A-Z]{2}\d{2}[A-Z]{2}\d{4}$/)
    .required()
    .messages({
      "string.base": "Vehicle number must be a string.",
      "any.required": "Vehicle number is required.",
    }),
  vehicle_type: Joi.string().required().messages({
    "string.base": "Vehicle type must be a string.",
    "any.required": "Vehicle type is required.",
  }),
  document_type: Joi.string()
    .valid("PAN Number", "Aadhar Number")
    .required()
    .messages({
      "any.only": "Document type must be either PAN Number or Aadhar Number.",
      "any.required": "Document type is required.",
    }),
  document_number: Joi.string().when(Joi.ref("document_type"), {
    switch: [
      {
        is: "PAN Number",
        then: Joi.string()
          .length(10) // Ensure length is 10
          .pattern(/^[A-Z]{5}\d{4}[A-Z]$/) // Validate the format
          .required()
          .messages({
            "string.base": "PAN number must be a string.",
            "string.length": "PAN number must be exactly 10 characters long.",
            "string.pattern.base": "PAN number is wrong.",
            "any.required": "PAN number is required.",
          }),
      },
      {
        is: "Aadhar Number",
        then: Joi.string()
          .length(12) // Ensure length is exactly 12
          .pattern(/^\d{12}$/) // Ensure it contains only digits
          .required()
          .messages({
            "string.length":
              "Aadhar number must be exactly 12 characters long.",
            "string.pattern.base": "Aadhar number must contain only digits.",
            "any.required": "Aadhar number is required.",
          }),
      },
    ],
    otherwise: Joi.string().required().messages({
      "any.required": "Document number is required.",
    }),
  }),
});

const signupSchema = Joi.object({
  first_name: Joi.string()
    .pattern(/^[A-Za-z]+$/)
    .min(3)
    .required()
    .messages({
      "string.base": "First name should be a type of text.",
      "string.empty": "First name cannot be empty.",
      "string.min": "First name should have a minimum length of 3 characters.",
      "string.pattern.base": "First name should contain only alphabets.",
      "any.required": "First name is required.",
    }),

  last_name: Joi.string()
    .pattern(/^[A-Za-z]+$/)
    .min(2)
    .max(50)
    .optional()
    .messages({
      "string.base": "Last name should be a type of text.",
      "string.empty": "Last name cannot be empty.",
      "string.min": "Last name should have a minimum length of 2 characters.",
      "string.max": "Last name should not exceed 50 characters.",
      "string.pattern.base": "Last name should contain only alphabets.",
      "any.required": "Last name is required.",
    }),

  email: Joi.string().email().required().messages({
    "string.base": "Email should be a type of text.",
    "string.email": "Email must be a valid email address.",
    "string.empty": "Email cannot be empty.",
    "any.required": "Email is required.",
  }),

  password: Joi.string().required().messages({
    "string.base": "Password should be a type of text.",
    "any.required": "Password is required.",
  }),

  country_code: Joi.string()
    .pattern(/^\+91$/)
    .required()
    .messages({
      "string.empty": "Country code cannot be empty.",
      "string.pattern.base": 'Country code must be "+91".',
      "any.required": "Country code is required.",
    }),

  phone_number: Joi.string()
    .pattern(/^\d{10}$/)
    .required()
    .messages({
      "string.empty": "Phone number cannot be empty.",
      "string.pattern.base": "Phone number must contain exactly 10 digits.",
      "any.required": "Phone number is required.",
    }),

  date_of_birth: Joi.date().iso().required().messages({
    "date.base": "Date of birth must be a valid date.",
    "date.format": "Date of birth must be in ISO format (YYYY-MM-DD).",
    "any.required": "Date of birth is required.",
  }),

  role_name: Joi.string()
    .valid("customer", "restaurant", "delivery_partner")
    .required()
    .messages({
      "any.only":
        "Role name must be one of customer, restaurant, or delivery_partner.",
      "any.required": "Role name is required.",
    }),

  other_details: Joi.any().when("role_name", {
    is: "customer",
    then: Joi.forbidden().messages({
      "any.unknown": "Other details should not be included for customers.",
    }),
    otherwise: Joi.object()
      .when("role_name", {
        is: "restaurant",
        then: restaurantSchema,
        otherwise: deliveryPartnerSchema,
      })
      .messages({
        "object.base": "Other details must be a valid JSON object.",
      })
      .required(), // Enforce presence of `other_details` for restaurant and delivery_partner
  }),
});

const checkUserExistenceSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.base": "Email should be a type of text.",
    "string.email": "Email must be a valid email address.",
    "string.empty": "Email cannot be empty.",
    "any.required": "Email is required.",
  }),
});

const loginWithGoogleSchema = Joi.object({
  role: Joi.string()
    .valid("admin", "delivery_partner", "customer", "restaurant")
    .required()
    .messages({
      "any.only":
        "Role must be one of [admin, delivery_partner, customer, restaurant].",
      "any.required": "Role is required.",
    }),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.base": "Email should be a type of text.",
    "string.email": "Please provide a valid email address.",
    "any.required": "Email is required.",
  }),
  password: Joi.string().min(8).required().messages({
    "string.base": "Password should be a type of text.",
    "string.min": "Password should be at least 8 characters.",
    "any.required": "Password is required.",
  }),
  role: Joi.string()
    .valid("admin", "delivery_partner", "customer", "restaurant")
    .required()
    .messages({
      "any.only":
        "Role must be one of [admin, delivery_partner, customer, restaurant].",
      "any.required": "Role is required.",
    }),
}).strict(); // ensures that no other fields are present

const logoutSchema = Joi.object({}).strict().required().messages({
  "object.base": "Request body must be empty.",
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.base": "Email should be a type of text.",
    "string.email": "Email must be a valid email address.",
    "string.empty": "Email cannot be empty.",
    "any.required": "Email is required.",
  }),
});

export {
  loginWithGoogleSchema,
  signupSchema,
  checkUserExistenceSchema,
  loginSchema,
  logoutSchema,
  forgotPasswordSchema,
};
