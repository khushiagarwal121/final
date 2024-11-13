const respondOk = (res, result = {}) => {
  res.status(200).send({ ...result, status: "Success" });
};

const respondError = (res, { statusCode, message }) => {
  res.status(statusCode).send({
    message,
  });
};

const respondRedirect = (res, result = {}, redirectCode = 303) => {
  res.status(redirectCode).json(result);
};

export { respondError, respondOk, respondRedirect };
