const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
var session = require("express-session");
var MySQLStore = require("express-mysql-session")(session);
const dotenv = require("dotenv");
const cors = require('cors');
const cookieparser = require('cookie-parser');

dotenv.config();

app.use(cookieparser());
app.set('trust proxy', 1);
const allowed_origin = 'http://localhost:3001';

const cors_options = {
  origin: allowed_origin,
  credentials: true,
};

app.use(cors(cors_options));

app.use(
	session({
		key: "session_cookie_name",
		secret: process.env.SESSION_COOKIE_SECRET,
		store: new MySQLStore({
			host: process.env.DB_HOST,
			port: 3306,
			user: process.env.DB_USER,
			password: process.env.DB_PASSWORD,
			database: process.env.DB_NAME,
		}),
		resave: false,
		saveUninitialized: false,
		cookie: {
			maxAge: 1000 * 60 * 60 * 24,
			httpOnly: true,
			sameSite: true,
			secure: false,//Set this to true when HTTPS is available !important
		},
	})
);

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


const connection = mysql.createConnection({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: "user",
	authPlugins: {
	  mysql_clear_password: () => () => Buffer.from(process.env.DB_PASSWORD + "\0")
	},
	multipleStatements: true,
  });
  

connection.connect((err) => {
	if (!err) {
		console.log("Connected");
	} else {
		console.log("Conection Failed" + err);
	}
});

const credentials = {usernameField: "uname",passwordField: "pw" };

const verifyCallback = (username, password, done) => {
    console.log("Verifying password for user " + username + "..." + password);
	connection.query("SELECT * FROM users WHERE username = ?", [username], function (error, results, fields) {
		if (error) {
            console.log('1' + error);
			return done(error);
		}

		if (results.length === 0) {
            console.log('2' + null, false);
			return done(null, false);
		}

		validPassword(password, results[0].hash, results[0].salt, (validErr, isValid) => {
			if (validErr) {
                console.log('3' + validErr);
				return done(validErr);
			}

			const user = {
				id: results[0].id,
				username: results[0].username,
				hash: results[0].hash,
				salt: results[0].salt,
			};

			if (isValid) {
                console.log('4' + null, user);
				return done(null, user);
			} else {
                console.log('5' + null, false);
				return done(null, false);
			}
		});
	});
};

passport.use( new LocalStrategy(credentials, verifyCallback));

passport.serializeUser((user, done) => {
	console.log("inside serialize " + user.username);
	done(null, user.id);
});

passport.deserializeUser(function (userId, done) {
	console.log("deserializeUser " + userId);
	connection.query("SELECT * FROM users where id = ?", [userId], function (error, results) {
		if (error) {
			done(error, null);
		} else {
			done(null, results[0]);
		}
	});
});



function validPassword(password, hash, salt, callback) {
	bcrypt.hash(password, salt, (err, hashVerify) => {
		if (err) {
			callback(err, null);
			return;
		}
		callback(null, hash === hashVerify);
	});
}

function genPassword(password, callback) {
	bcrypt.genSalt(10, (saltErr, salt) => {
		if (saltErr) {
			callback(saltErr, null);
			return;
		}

		bcrypt.hash(password, salt, (hashErr, genhash) => {
			if (hashErr) {
				callback(hashErr, null);
				return;
			}
			callback(null, { salt, hash: genhash });
		});
	});
}

function isAuth(req, res, next) {
	if (req.isAuthenticated()) {
		next();
	} else {
		res.redirect("/notAuthorized");
	}
}

function isAdmin(req, res, next) {
	if (req.isAuthenticated() && req.user.isAdmin == 1) {
		next();
	} else {
		res.redirect("/notAuthorizedAdmin");
	}
}

function userExists(req, res, next) {
	connection.query("Select * from users where username=? ", [req.body.uname], function (error, results, fields) {
		if (error) {
			console.log("Error");
		} else if (results.length > 0) {
			res.send("<p>User already exists!</p>");
		} else {
			next();
		}
	});
}

function userControl(req, res, next){
	console.log('userControl has been executed');
	global.stored_username = req.user.username;
	global.stored_ip = req.ip;
	next();
  };
  


app.use((req, res, next) => {
    console.log('from app use req res line 174');
	console.log(req.session);
	console.log(req.user);
	next();
});

app.get("/", (req, res, next) => {
	res.send('<h1>Home</h1><p>Please <a href="/register">register</a></p>');
});



app.get("/logout", isAuth, (req, res) => {

	res.clearCookie('session_cookie_name');
	res.send(`<h1>Logged out ${req.user.username} </h1><p></p>`);
	stored_username = null;
    req.logout();
	
});


app.get("/login-success", (req, res, next) => {
    if (req.isAuthenticated()) {
        res.send(`Welcome, ${req.user.username}! You successfully logged in.${req.ip}`);
    } else {
        res.redirect("/login");
    }
});


app.get("/login-failure", (req, res, next) => {
	res.send("You entered the wrong password.");	
});

app.get("/register", (req, res, next) => {
	res.render("register");
});

app.post("/register", userExists, (req, res, next) => {
	console.log("Inside post");
	console.log(req.body.pw);

	genPassword(req.body.pw, (genErr, saltHash) => {
		if (genErr) {
			return;
		}

		const salt = saltHash.salt;
		const hash = saltHash.hash;

		connection.query("INSERT INTO users (username, hash, salt, isAdmin) VALUES (?, ?, ?, 0)", [req.body.uname, hash, salt], function (error, results, fields) {
			if (error) {
				console.log("Error");
			} else {
				console.log("Successfully Entered");
				res.redirect("/login");
			}
		});
	});
});

//important login
app.post("/login", passport.authenticate("local", { 
	failureRedirect: "/login-failure",
	successRedirect: "/login-success",
	failureFlash: false
 }));

 app.get('/check-username/:username', (req, res) => {
    const usernameToCheck = req.params.username;

	if(usernameToCheck !== null){

    connection.query("SELECT COUNT(*) AS count FROM users WHERE username = ?", [usernameToCheck], function (error, results, fields) {
        if (error) {
            console.error(error);
            return res.status(500).json({ error: 'Database error' });
        }

        const count = results[0].count;

        if (count > 0) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    });
}
});


app.get("/protected-route", isAuth, (req, res, next) => {
	res.send( stored_username + 'You are authenticated');
});

app.get("/admin-route", isAdmin, (req, res, next) => {
	res.send('You are admin');
});

app.get("/notAuthorized", (req, res, next) => {
	console.log("Inside get");
	res.send(stored_username + 'You are not authorized to view the resource');
});

app.get("/notAuthorizedAdmin", (req, res, next) => {
	console.log("Inside get");
	res.send('You are not authorized to view the resource as you are not the admin of the page');
});

app.get("/userAlreadyExists", (req, res, next) => {
	console.log("Inside get");
	res.send('Sorry This username is taken>');
});

app.listen(3000, function () {
	console.log("App listening on port " );
});