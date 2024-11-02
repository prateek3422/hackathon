import mongoose from "mongoose";

const connectDb = async () => {
  try {
    const connection = await mongoose.connect(
      "mongodb://localhost:27017/test1"
    );
    console.log(`mangodb connection success ${connection.connection.host}`);
  } catch (error) {
    console.log("mangodb connection faild ", error);
  }
};

export default connectDb;
