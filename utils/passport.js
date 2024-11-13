import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import passport from "passport";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_REDIRECT_URI,
    },
    async (accessToken, refreshToken, profile, callback) => {
      try {
        const {
          email,
          given_name: first_name,
          family_name: last_name,
        } = profile._json;

        callback(null, { email, first_name, last_name });
      } catch (error) {
        callback(error);
      }
    }
  )
);

export default passport;
