import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"

const app = express();
const port = 3000;
const saltRounds = 10;


const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "13837386",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //password Hashing
      bcrypt.hash(password, saltRounds, async(err,hash)=>{
       if (err) {
        console.log("Error hashing Password:",err);
       }else{
        const result = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2)",
          [email, hash]
        );
        res.redirect("/");
      }
      })
     
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;
   try {
     const result = await db.query("SELECT * FROM users WHERE email = $1", [
       email,
     ]);

     if (result.rows.length > 0) {
       const user = result.rows[0]
       const storedHashPassword = user.password

       bcrypt.compare(loginPassword,storedHashPassword,(err,result)=>{
        if (err) {
          console.log("Error comparing password:",err);
        }else{
          if (result) {
            res.render("secrets.ejs")
          }else{
            res.send("Your password is not correct")
          }  
        }
       })
     }else{
       res.send("User is not found")
     }
   } catch (error) {
    console.log(error)
   }
    
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
