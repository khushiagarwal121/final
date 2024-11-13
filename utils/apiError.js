class ApiError extends Error {
  /**
   * @param {string} message - Error message
   * @param {number} statusCode - HTTP status code
   */
  constructor(message, statusCode) {
    super(message);

    this.statusCode = statusCode || 500;

    // Determine error status based on status code range
    this.status = this.determineErrorStatus(this.statusCode);

    // Add timestamp for error tracking
    this.timestamp = new Date().toISOString();

    this.message =
      this.statusCode === 500
        ? `${this.status} : Something went wrong, please try again later!`
        : `${this.status} : ${this.message}`;
  }

  /**
   * Determines the error status based on HTTP status code
   * @param {number} statusCode
   * @returns {string}
   */
  determineErrorStatus(statusCode) {
    if (statusCode >= 400 && statusCode < 500) {
      switch (statusCode) {
        case 400:
          return "Bad Request";
        case 401:
          return "Unauthorized";
        case 403:
          return "Forbidden";
        case 404:
          return "Not Found";
        case 429:
          return "Too Many Requests";
        default:
          return "Client Error";
      }
    }
    if (statusCode >= 500) {
      switch (statusCode) {
        case 500:
          return "Internal Server Error";
        case 502:
          return "Bad Gateway";
        case 503:
          return "Service Unavailable";
        default:
          return "Server Error";
      }
    }
    return "Unknown Error";
  }
}

export default ApiError;
