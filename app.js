import express from "express";
import { rateLimit } from "express-rate-limit";
import cookieParser from "cookie-parser";
import cors from "cors";

import authRouter from "./features/auth/authApi.js";
import { respondError } from "../../utils/responseHandler.js";

const app = express();

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  limit: 1000,
  message:
    "We have recieved too many requests from your side. Please try again after 1 hour.",
});

app.use(express.json());
app.use(cookieParser());
app.use(limiter);
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use("/api/v1/auth", authRouter);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.all("*", (req, res) => {
  respondError(res, {
    message: "The route you are trying to access does not exist.",
    statusCode: 404,
  });
});

export default app;
