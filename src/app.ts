import express from "express";
import cookieParser from "cookie-parser";
import { errorHandler } from "./middlewares/error.middleware";
import { authRoutes } from "./routes/auth.routes";

const app = express();

declare global {
  namespace Express {
    interface Request {
      user: any;
    }
  }
}

//* middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

//* routes
app.use("/api/auth", authRoutes);

app.use(errorHandler);
export default app;
