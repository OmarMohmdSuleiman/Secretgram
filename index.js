// Import required modules
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";
import session from "express-session";

const app = express(); //Initialize the express app
const port = 4000; // Port of the server
const saltRounds = 10; // Number of salt rounds

env.config(); // Load the variables from .env

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public")); // Look inside the public folder

// Set the session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

// Connect to PostgreSQL database 
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
  db.connect();

 // Route for the pages in the app through GET
app.get("/", (req, res) => {
    res.render("index.ejs");
  });

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});
app.get("/login", (req, res) => {
    
    res.render("login.ejs");  
});

app.get("/secrets", async (req, res) => {
  console.log("User Email in session (before rendering):", req.session.userEmail);  // Log the session email
  if (req.session.userAuthorized) {
    // Fetch the user's secret from the database using the stored email in the session
    const result = await db.query("SELECT secrettext FROM user_info WHERE email = $1", [req.session.userEmail]);
    const userSecret = result.rows[0] ? result.rows[0].secrettext : ''; // Default to empty if no secret

    // Render the secrets page with the user's secret if there is secret
    res.render("secrets.ejs", { secret: userSecret });
  } else {
    res.redirect("/login");
  }
});

 // Route for the pages in the app through POST
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

    // Successful login, set session variables
    req.session.userAuthorized = true;
    req.session.userEmail = user.email;  // Store the user's email in the session

    console.log("Logged in as:", req.session.userEmail);  // Log email to verify it's set

    // Redirect to the secrets page after successful login
    res.redirect("/secrets");
  } catch (err) {
    console.error("Error during login:", err);
    return res.status(500).send("Server error during login.");
  }
});




app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Check if the user already exists
    const checkResult = await db.query("SELECT * FROM user_info WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      // User already exists, redirect to login page with message
      return res.redirect("/login?message=User%20already%20exists");
    } else {
      // Hash the password
      const hash = await bcrypt.hash(password, saltRounds);

      // Insert user into the database
      const result = await db.query(
        "INSERT INTO user_info (email, password) VALUES ($1, $2) RETURNING *",
        [email, hash]
      );

      const user = result.rows[0]; // Get the inserted user details
      console.log("User registered:", user);

      // Set session variables
      req.session.userAuthorized = true;
      req.session.userEmail = email;  // Store email in the session for authentication

      // Redirect to secrets page after successful registration
      return res.redirect("/secrets");
    }
  } catch (err) {
    console.log(err);
    return res.status(500).send("Error during registration.");
  }
});

app.post("/secrets", async (req, res) => {
  const userSecret = req.body.secret;

  if (req.session.userAuthorized) {
    try {
      // Update the secret in the database for the logged-in user
      await db.query(
        `UPDATE user_info SET secrettext = $1 WHERE email = $2`,
        [userSecret, req.session.userEmail]  // Use session email
      );
      
      console.log("Secret updated successfully");
      res.redirect("/secrets");  // Redirect to secrets page after updating
    } catch (err) {
      console.log("Error updating secret:", err);
      res.status(500).send("Error updating secret.");
    }
  } else {
    // If not authorized, redirect to login
    res.redirect("/login");
  }
});
  

app.get("/logout", (req, res) => {
  // Destroy the session and all session data
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error during logout.");
    }
    // Redirect to the login page after successful logout
    res.redirect("/login");
  });
});

// Start the Express server on port 4000
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
