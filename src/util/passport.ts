import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { ApiError } from "./apiError";
import { User } from "../models/auth.model";

try {
  passport.serializeUser((user: any, next) => {
    next(null, user?._id);
  });

  passport.deserializeUser((id, next) => {
    try {
      const user = User.findById(id);
      if (user) {
        return next(null, user);
      } else {
        return next(new ApiError(404, "User not found"));
      }
    } catch (error: any) {
      return next(new ApiError(500, "Error in deserializeUser", error));
    }
  });

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        callbackURL: process.env.GOOGLE_CALLBACK_URL!,
      },
      async (accessToken, refreshToken, profile, next) => {
        try {
          const isUser = await User.findOne({ googleId: profile.id });
          if (isUser) {
            if (isUser.LoginType !== "google") {
              return next(
                new ApiError(401, "User already exists with this email")
              );
            } else {
              return next(null, isUser);
            }
          } else {
            const newUser = new User({
              Fullname: profile._json.name,
              Username: profile._json.name,
              email: profile._json.email,
              password: profile._json.sub,
              LoginType: profile.provider,
              isEmailVerified: profile._json.email_verified,
              role: "user",
            });

            if (newUser) {
              return next(null, newUser);
            }
          }
        } catch (error: any) {
          return next(new ApiError(500, "Error in Google log in", error));
        }
      }
    )
  );
} catch (error) {
  console.log(error);
}
