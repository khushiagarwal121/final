export const validatePassword = (password) => {
  const minLength = /.{8,}/; // At least 8 characters
  const hasLowercase = /[a-z]/; // At least one lowercase letter
  const hasUppercase = /[A-Z]/; // At least one uppercase letter
  const hasDigit = /[0-9]/; // At least one digit
  const hasSpecialChar = /[@$!%*?&]/; // At least one special character

  if (!minLength.test(password)) {
    return "Password must be at least 8 characters long.";
  }
  if (!hasLowercase.test(password)) {
    return "Password must contain at least one lowercase letter.";
  }
  if (!hasUppercase.test(password)) {
    return "Password must contain at least one uppercase letter.";
  }
  if (!hasDigit.test(password)) {
    return "Password must contain at least one digit.";
  }
  if (!hasSpecialChar.test(password)) {
    return "Password must contain at least one special character.";
  }

  return true;
};
