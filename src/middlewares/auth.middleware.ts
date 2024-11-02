import { NextFunction, Request, Response } from "express";
import { ApiError } from "../util";
import jwt from "jsonwebtoken";
import { User } from "../models/auth.model";

const jwtVerify = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req?.cookies?.accessToken;

    if (!token) {
      return next(new ApiError(401, "invalid token"));
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN as string);

    if (!decodedToken) {
      return next(new ApiError(401, "unauthorized token"));
    }

    //@ts-ignore
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshTokens -otp "
    );

    if (!user) {
      return next(new ApiError(401, "Invalid Access Token"));
    }

    //@ts-ignore
    req.user = user;

    next();
  } catch (error: any) {
    return next(new ApiError(401, error.message || "Invalid Access Token"));
  }
};

export { jwtVerify };
