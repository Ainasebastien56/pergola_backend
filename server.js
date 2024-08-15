const express= require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { query } = require('express');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

//connexion with mysql
const db = mysql.createConnection({
host :process.env.DB_HOST,
user:process.env.DB_USER,
password:process.env.DB_PASS,
database:'authdb'
});

db.connect((err)=>{
    if(err) throw err;
    console.log('Mysql connected...');
})

// creation of user table if it's not exist
db.query(
    `CREATE TABLE IF NOT EXISTS users(
     id INT AUTO_INCREMENT PRIMARY KEY,
     email VARCHAR(255) UNIQUE,
     password VARCHAR(255)   
    )`,
    (err,result)=>{
        if(err) throw err;
        console.log('Table created or already exists');
    }
); 


//Register Route
app.post('/register',async(req,res)=>{
    const {email, password} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword],
        (err, result)=>{
            if(err){
                if(err.code === 'ER_DUP_ENTRY'){
                    return res.status(400).json({error: 'Username already exist!'})  
                }
             throw err;       
            }
            res.status(201).json({message:'User registered successfully!'
            });
        }
    );
});

//Login Route
app.post('/login',(req,res)=>{
    const {email, password} = req.body;

    db.query('SELECT * FROM users WHERE email =?',
    [email],async(err,results)=>{
        if(err) throw err;
        if(results.length === 0){
            return res.status(400).json({error:'User not found!'});
        }

        const user =  results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if(!isPasswordValid){
            return res.status(400).json({error:'Invalid password'});   
        }

        const token = jwt.sign({id: user.id}, process.env.JWT_SECRET, {expiresIn:'1h'});
        res.json({token});
    });

});


// protect Route
app.get('/protected', (req, res) => {
    const token = req.headers.authorization
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid token' });
      }
      res.json({ message: 'This is a protected route', user });
    });
  });

  app.get('/userInfos',(req, res)=>{
      const token =  req.headers.authorization
      console.log(token)
      if(!token){
        return res.status(401).json({ error: 'Unauthorized' });
      }
      jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
          return res.status(403).json({ error: 'Invalid token' });
        }
        console.log(user.id)
        db.query('SELECT * FROM users WHERE id = ?',[user.id], async(err,results)=>{
            if(err) throw err;
            if(results.length === 0){
                return res.status(400).json({error:'User not found!'})
            }
            const user = results[0];
            return res.status(201).json(user);
        })
      });
  })

app.listen(5000, ()=>{
    console.log('Serveur running on port 5000');
})