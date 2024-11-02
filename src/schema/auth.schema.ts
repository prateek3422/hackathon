import { z } from "zod";

const registerSchema = z.object({
  Fullname: z.string().min(3).max(255),
  Username: z.string().min(3).max(255),
  email: z.string().email(),
  password: z.string().min(6).max(255),
});

const signinrSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6).max(255),
});

const verifyOtp = z.object({
  otp: z.string().min(6).max(6),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resendEmailSchema = z.object({
  email: z.string().email(),
});

const verifyForgotPasswordSchema = z.object({
  otp: z.string().min(6).max(6),
  password: z.string().min(6).max(255),
});

const updateUserSchema = z.object({
  Fullname: z.string().min(3).max(255),
  Username: z.string().min(3).max(255),
});

export {
  registerSchema,
  signinrSchema,
  verifyOtp,
  resendEmailSchema,
  forgotPasswordSchema,
  verifyForgotPasswordSchema,
  updateUserSchema,
};
