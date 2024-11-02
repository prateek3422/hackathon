import Router from "express";
import { jwtVerify } from "../middlewares/auth.middleware";

import {
  createUser,
  deleteUser,
  forgotPassword,
  getCurrentUser,
  resendEmail,
  signinUser,
  signOutUser,
  updateUser,
  verifyEmail,
  verifyForgotPassword,
} from "../controllers/auth.controllers";

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

export { router as authRoutes };
