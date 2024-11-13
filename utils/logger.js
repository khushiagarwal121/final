import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import path from "path";
import { fileURLToPath } from "url";

const { combine, timestamp, json } = winston.format;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const transport = new DailyRotateFile({
  filename: "food-delivery-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  dirname: path.join(__dirname, "../logs"), // directory where log files will be saved
  zippedArchive: true, // old logs will be compressed to .gz format
  maxSize: "20m", // rotates log after 20mb is hit
  maxFiles: "14d", // max duration for which logs are kept
});

const logger = winston.createLogger({
  level: "info",
  format: combine(
    timestamp({
      format: "YYYY-MM-DD hh:mm:ss A",
    }),
    json()
  ),
  transports: [transport, new winston.transports.Console()],
});

export default logger;
