import Router from "express";
import { jwtVerify } from "../middlewares/auth.middleware";

import {
  createUser,
  deleteUser,
  forgotPassword,
  getCurrentUser,
  handleSocilaLogin,
  resendEmail,
  signinUser,
  signOutUser,
  updateUser,
  verifyEmail,
  verifyForgotPassword,
} from "../controllers/auth.controllers";
import passport from "passport";

const router = Router();

router.route("/Signup").post(createUser);
router.route("/Signin").post(signinUser);
router.route("/current").get(jwtVerify, getCurrentUser);
router.route("/Signout").post(jwtVerify, signOutUser);
router.route("/verifyEmail").post(jwtVerify, verifyEmail);
router.route("/resendEmail").post(jwtVerify, resendEmail);
router.route("/forgotPassword").post(jwtVerify, forgotPassword);
router.route("/verifyForgotPassword").post(jwtVerify, verifyForgotPassword);
router.route("/delete").delete(jwtVerify, deleteUser);
router.route("/update").patch(jwtVerify, updateUser);

//social login

router
  .route("/google")
  .get(
    passport.authenticate("google", { scope: ["profile", "email"] }),
    (req, res) => {
      res.send("redirecting to google...");
    }
  );

router
  .route("/google/callback")
  .get(passport.authenticate("google"), handleSocilaLogin);

export { router as authRoutes };
