import express from "express";
import cookieParser from "cookie-parser";
import { errorHandler } from "./middlewares/error.middleware";
import { authRoutes } from "./routes/auth.routes";
import passport from "passport";
import session from "express-session";

const app = express();

declare global {
  namespace Express {
    interface Request {
      //@ts-ignore
      user: any;
    }
  }
}

//*passport config
app.use(
  session({
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
passport.session();

//* middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

//* routes
app.use("/api/auth", authRoutes);

app.use(errorHandler);
export default app;
