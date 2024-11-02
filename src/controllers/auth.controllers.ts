import { NextFunction, Request, Response } from "express";
import { User } from "../models/auth.model";
import { ApiError, ApiResponse } from "../util";
import asynchandler from "../util/asynchandler";
import {
  forgotPasswordSchema,
  registerSchema,
  resendEmailSchema,
  signinrSchema,
  updateUserSchema,
  verifyForgotPasswordSchema,
  verifyOtp,
} from "../schema";
import { generateOtp } from "../util/genrateOtp";
import { sendEmail, SendEmailVerification } from "../util/SendMails";
import jwt from "jsonwebtoken";

const genrateAccessAndRefreshToken = async (userId: string) => {
  try {
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(404, "user not found");
    }

    const accessToken = await user.CreateAccessToken();
    const refreshToken = await user.CreateRefreshToken();

    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    console.log(error);
    throw new ApiError(500, "Something error while genrating token");
  }
};

const createUser = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { Fullname, Username, email, password } = registerSchema.parse(
      req.body
    );

    const isEmail = await User.findOne({ $or: [{ email }, { Username }] });

    if (isEmail) {
      return next(new ApiError(400, "Email or Username already"));
    }

    const user = await User.create({
      Fullname,
      Username,
      email,
      password,
    });

    user.otp = generateOtp();
    //@ts-ignore
    const token = await user.generatetokens(user.otp, user?._id);
    await user.save({ validateBeforeSave: false });

    await sendEmail({
      email: user.email,
      subject: "Email verification",
      MailgenContent: SendEmailVerification(user.Username, user.otp),
    });

    const createdUser = await User.findById(user._id).select(
      "-password -refreshTokens -otp"
    );

    if (!createdUser) {
      return next(
        new ApiError(400, "Something went wrong while creating user")
      );
    }
    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60,
    };

    res
      .status(200)
      .cookie("otp", token, options)
      .json(new ApiResponse(200, {}, "user registerd successfully"));
  }
);

const verifyEmail = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { otp } = verifyOtp.parse(req.body);
    const token = req.cookies?.verifyUser;

    if (!token) {
      return next(new ApiError(401, "invalid token"));
    }

    const decodedToken = await jwt.verify(
      token,
      process.env.OTPSECRET as string
    );

    //@ts-ignore
    if (decodedToken?.otp !== otp) {
      return next(new ApiError(401, "invalid otp"));
    }

    //@ts-ignore
    const user = await User.findById(decodedToken.id);

    if (!user) {
      return next(new ApiError(400, "invalid otp"));
    }

    user.isEmailVerified = true;
    user.otp = undefined;

    await user.save({ validateBeforeSave: false });

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60,
    };
    return res
      .status(201)
      .clearCookie("verifyUser", options)
      .json(new ApiResponse(201, user, "Email verified successfully"));
  }
);

const resendEmail = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = resendEmailSchema.parse(req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return next(new ApiError(400, "user not found"));
    }

    if (user.isEmailVerified) {
      return next(new ApiError(400, "email is already verified"));
    }

    user.otp = generateOtp();

    const token = await user.generatetokens(user.otp, user.id);

    await user.save({ validateBeforeSave: false });

    sendEmail({
      email: user.email,
      subject: "Email verification",
      MailgenContent: SendEmailVerification(user.Username, user.otp),
    });

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60,
    };
    return res
      .status(204)
      .cookie("verifyUser", token, options)
      .json(new ApiResponse(200, {}, "email resend successfully"));
  }
);

const forgotPassword = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = forgotPasswordSchema.parse(req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return next(new ApiError(400, "check your email"));
    }

    user.otp = generateOtp();
    const token = await user.generatetokens(user.otp, user.id);
    await user.save({ validateBeforeSave: false });

    sendEmail({
      email: user.email,
      subject: "Email verification",
      MailgenContent: SendEmailVerification(user.Username, generateOtp()),
    });

    const option = {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60,
    };

    return res
      .status(200)
      .cookie("verifyUser", token, option)
      .json(new ApiResponse(200, {}, "forgot password successfully"));
  }
);

const verifyForgotPassword = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { otp, password } = verifyForgotPasswordSchema.parse(req.body);

    const token = req.cookies?.verifyUser;
    if (!token) {
      return next(new ApiError(401, "invalid token"));
    }

    const decodedToken = await jwt.verify(
      token,
      process.env.OTPSECRET as string
    );
    //@ts-ignore
    if (decodedToken?.otp !== otp) {
      return next(new ApiError(401, "invalid otp"));
    }

    //@ts-ignore
    const user = await User.findById(decodedToken.id).select(
      "-password -refreshToken"
    );

    if (!user) {
      return next(new ApiError(400, "invalid otp"));
    }

    user.password = password;
    user.otp = undefined;

    await user.save({ validateBeforeSave: false });

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60,
    };
    return res
      .status(201)
      .clearCookie("verifyUser", options)
      .json(new ApiResponse(201, user, "Email verified successfully"));
  }
);

const signinUser = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = signinrSchema.parse(req.body);

    const user = await User.findOne({ email });

    if (!user) {
      return next(new ApiError(400, "invalid credentials"));
    }

    const isMatchPassword = await user.checkPassword(password);

    if (!isMatchPassword) {
      return next(new ApiError(400, "invalid credentials"));
    }

    const { accessToken, refreshToken } = await genrateAccessAndRefreshToken(
      user.id
    );

    const logedInUser = await User.findById(user._id).select(
      "-password -refreshToken -otp "
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(new ApiResponse(200, logedInUser, "user signin successfully"));
  }
);

const getCurrentUser = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const user = await User.findById(req.user?._id).select(
      "-password -refreshToken"
    );
    return res
      .status(200)
      .json(new ApiResponse(200, user, "signout successfully"));
  }
);

const signOutUser = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    await User.findByIdAndUpdate(
      req.user?._id,
      {
        $unset: {
          refreshToken: 1,
        },
      },
      {
        new: true,
      }
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new ApiResponse(200, {}, "signout successfully"));
  }
);
const updateUser = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { Fullname, Username } = updateUserSchema.parse(req.body);
    const user = await User.findById(req.user?._id);

    if (!user) {
      return next(new ApiError(404, "user not found"));
    }

    const updated = await User.findByIdAndUpdate(
      req.user?._id,
      { Fullname, Username },
      { new: true }
    );

    return res
      .status(200)
      .json(new ApiResponse(200, updated, "user updated successfully"));
  }
);

const deleteUser = asynchandler(
  async (req: Request, res: Response, next: NextFunction) => {
    await User.findByIdAndDelete(req.user?._id);
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "user delete successfully"));
  }
);

export {
  genrateAccessAndRefreshToken,
  createUser,
  signOutUser,
  signinUser,
  getCurrentUser,
  deleteUser,
  verifyEmail,
  resendEmail,
  forgotPassword,
  updateUser,
  verifyForgotPassword,
};
