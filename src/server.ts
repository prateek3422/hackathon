import dotenv from "dotenv";
dotenv.config({ path: "./.env.local" });
import app from "./app";
import connectDb from "./database";
const port = process.env.PORT || 5000;

connectDb()
  .then(() => {
    console.log("database connected");
  })
  .catch((error) => {
    console.log("server error", error);
  });

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
