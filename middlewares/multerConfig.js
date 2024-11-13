import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import ApiError from "../utils/apiError.js";

const allowedMimeTypes = {
  images: ["image/jpeg", "image/jpg", "image/png", "image/gif"],
  documents: ["application/pdf"],
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Define your storage path
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = uuidv4();
    const extension = path.extname(file.originalname);
    cb(null, `${uniqueSuffix}.${extension}`);
  },
});

const fileFilter = (req, file, cb) => {
  const isImage = allowedMimeTypes.images.includes(file.mimetype);
  const isDocument = allowedMimeTypes.documents.includes(file.mimetype);

  if (!isImage && !isDocument) {
    return cb(
      new ApiError(
        "File type not allowed. Only images and documents are allowed.",
        400
      ),
      false
    );
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
});

export default upload;
