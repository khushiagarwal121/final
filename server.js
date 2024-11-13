// Handle Uncaught Exceptions (synchronous errors) at the start
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception! Shutting down...");
  console.error(`${err.name}: ${err.message}`);
  process.exit(1); // Immediate exit as the app is in an unstable state
});

import databaseConfig from "./models/index.js";
import app from "./app.js";

const port = process.env.PORT || 3000;

// Start the server
const server = app.listen(port, () => {
  databaseConfig.connectDB();
  console.log(`Server is up and running on ${port}`);
});

// Handle Unhandled Promise Rejections (asynchronous errors)
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection! Shutting down...");
  console.error(`${err.name}: ${err.message}`);

  // Close the server gracefully before exiting
  server.close(() => {
    process.exit(1);
  });
});
