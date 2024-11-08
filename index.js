import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";
import session from "express-session";

const app = express();
const port = 4000;
const saltRounds = 10;
const userAuthorized=false;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
  db.connect();

app.get("/", (req, res) => {
    res.render("index.ejs");
  });

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});
app.get("/login", (req, res) => {
    
    res.render("login.ejs");  
});
app.get("/secrets", (req, res) => {
    res.render("secrets.ejs");
});



app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
  
    try {
      // Check if user already exists
      const checkResult = await db.query("SELECT * FROM user_info WHERE email = $1", [email]);
  
      if (checkResult.rows.length > 0) {
        // User already exists, redirect to login page with message
        return res.redirect("/login");
      } else {
        // Hash the password
        const hash = await bcrypt.hash(password, saltRounds);
  
        // Insert user into the database
        const result = await db.query(
          "INSERT INTO user_info (email, password) VALUES ($1, $2) RETURNING *",
          [email, hash]
        );
  
        const user = result.rows[0]; // Get the inserted user details
        console.log(user);
  
        // Redirect to secrets page after successful registration
        return res.redirect("/secrets");
      }
    } catch (err) {
      console.log(err);
      return res.status(500).send("Error checking user in the database.");
    }
  });
  app.post("/login", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
  
    try {
      // Check if the user exists in the database
      const checkUser = await db.query("SELECT * FROM user_info WHERE email = $1", [email]);
  
      if (checkUser.rows.length === 0) {
        // User does not exist, redirect with an error message
        return res.redirect("/login?message=User%20does%20not%20exist");
      }
  
      const user = checkUser.rows[0];
  
      // Compare the hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);
  
      if (!isPasswordValid) {
        // Incorrect password, redirect with an error message
        return res.redirect("/login?message=Incorrect%20password");
      }
  
      // Successful login, redirect to secrets page
      return res.redirect("/secrets");
    } catch (err) {
      console.error("Error during login:", err);
      return res.status(500).send("Server error during login.");
    }
  });
  


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
