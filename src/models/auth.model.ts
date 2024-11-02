import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

interface Iuser extends Document {
  Fullname: string;
  Username: string;
  email: string;
  password: string;
  refreshToken: string | null;
  isEmailVerified: boolean;
  LoginType: string;
  otp: number | undefined;
  createdAt: Date;
  updatedAt: Date;

  checkPassword(password: string): Promise<boolean>;
  CreateAccessToken: () => string;
  CreateRefreshToken: () => string;
  generatetokens: (otp: number, id: string) => Promise<string>;
}

const userSchema = new Schema<Iuser>(
  {
    Fullname: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },

    Username: {
      type: String,
      required: true,
      lowercase: true,
      index: true,
      trim: true,
    },

    email: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    LoginType: {
      type: String,
      enum: ["email-password", "google", "github"],
      default: "email-password",
    },
    otp: { type: String },
    refreshToken: { type: String },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.checkPassword = async function (password: string) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.CreateAccessToken = function () {
  return jwt.sign(
    { _id: this._id, username: this.username, email: this.email },
    process.env.ACCESS_TOKEN as string,
    { expiresIn: process.env.EXPAIRE_ACCESS_tOKEN! }
  );
};

userSchema.methods.CreateRefreshToken = function () {
  return jwt.sign({ _id: this._id }, process.env.REFRESH_TOKEN as string, {
    expiresIn: process.env.EXPAIRE_REFRESH_tOKEN!,
  });
};

userSchema.methods.generatetokens = async function (otp: string, id: string) {
  return jwt.sign({ otp, id }, process.env.OTPSECRET as string, {
    expiresIn: process.env.OTP_EXPAIRY,
  });
};

export const User = mongoose.model<Iuser>("User", userSchema);
