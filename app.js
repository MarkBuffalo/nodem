// app.js

const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const ejsMate = require('ejs-mate');
const csrf = require('csurf');
const multer = require('multer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const FileType = require('file-type'); // Importing file-type compatible with CommonJS
const helmet = require('helmet');

const app = express();

// Use helmet for security headers
app.use(helmet());

// Set up session middleware
app.use(
    session({
        secret: 'your_actual_secret_key', // Use a strong secret key
        resave: false,
        saveUninitialized: false, // Do not save uninitialized sessions
        cookie: {
            httpOnly: true, // Helps prevent XSS
            secure: process.env.NODE_ENV === 'production', // Ensure cookies are sent over HTTPS in production
            sameSite: 'lax',
        },
    })
);

// Initialize CSRF protection middleware
const csrfProtection = csrf();

// Set up EJS with ejs-mate for layout support
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false }));

// Middleware to make 'session' and helper functions available in EJS templates
app.use((req, res, next) => {
    res.locals.session = req.session;
    res.locals.highlightTerm = function (text, term) {
        const escapedText = validator.escape(text);
        const escapedTerm = validator.escape(term);
        const regex = new RegExp(`(${escapedTerm})`, 'gi');
        return escapedText.replace(regex, '<span class="highlight">$1</span>');
    };
    next();
});

// Error handling middleware for CSRF errors
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        res.status(403);
        res.render('error', { message: 'Form tampered with', error: err });
    } else {
        next(err);
    }
});

// Set up Multer storage (in-memory)
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
});

// Database setup
const db = new sqlite3.Database('database.db');

// Create tables if they don't exist
db.serialize(() => {
    db.run(
        `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      bio TEXT,
      avatar TEXT,
      reset_token TEXT,
      reset_token_expires DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
    );

    db.run(
        `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`
    );
});

// Rate limiter for posting
const postLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5, // Limit each IP to 5 posts per windowMs
    message: 'Too many posts from this IP, please try again later.',
});

// Rate limiter for registration
const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 registration attempts per windowMs
    message: 'Too many registration attempts from this IP, please try again later.',
});

// Rate limiter for login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login attempts per windowMs
    message: 'Too many login attempts from this IP, please try again later.',
});

// Helper function to render the index page with optional error message
function renderIndexPage(req, res, error = null) {
    const page = parseInt(req.query.page) || 1; // Current page number
    const limit = 10; // Posts per page
    const offset = (page - 1) * limit;

    // Count total posts
    db.get(`SELECT COUNT(*) AS count FROM posts`, [], (err, result) => {
        if (err) {
            console.error(err);
            return res.render('error', { message: 'An error occurred', error: err });
        }
        const totalPosts = result.count;
        const totalPages = Math.ceil(totalPosts / limit);

        // Fetch posts for current page
        db.all(
            `SELECT posts.*, users.username, users.avatar
       FROM posts
       JOIN users ON posts.user_id = users.id
       ORDER BY posts.created_at DESC
       LIMIT ? OFFSET ?`,
            [limit, offset],
            (err, posts) => {
                if (err) {
                    console.error(err);
                    return res.render('error', { message: 'An error occurred', error: err });
                }
                res.render('index', {
                    posts,
                    currentPage: page,
                    totalPages,
                    error,
                    csrfToken: req.csrfToken(),
                });
            }
        );
    });
}

// Home Route
app.get('/', csrfProtection, (req, res) => {
    renderIndexPage(req, res);
});

// Handle New Post
app.post('/post', csrfProtection, postLimiter, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    let { content } = req.body;
    const userId = req.session.user.id;

    // Basic validation
    if (!content || content.trim() === '') {
        return renderIndexPage(req, res, 'Post content cannot be empty.');
    }

    // Sanitize the content
    content = validator.escape(content);

    db.run(
        `INSERT INTO posts (user_id, content) VALUES (?, ?)`,
        [userId, content],
        (err) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }
            res.redirect('/');
        }
    );
});

// Registration Page
app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { error: null, csrfToken: req.csrfToken() });
});

// Handle Registration
app.post('/register', csrfProtection, registerLimiter, (req, res) => {
    const { username, email, password, confirm_password } = req.body;

    // Input validation
    if (!validator.isAlphanumeric(username) || username.length < 3 || username.length > 20) {
        return res.render('register', {
            error: 'Username must be alphanumeric and 3-20 characters long.',
            csrfToken: req.csrfToken(),
        });
    }

    if (!validator.isEmail(email)) {
        return res.render('register', {
            error: 'Invalid email address.',
            csrfToken: req.csrfToken(),
        });
    }

    if (password !== confirm_password) {
        return res.render('register', { error: 'Passwords do not match', csrfToken: req.csrfToken() });
    }

    if (
        !validator.isStrongPassword(password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
        })
    ) {
        return res.render('register', {
            error:
                'Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol.',
            csrfToken: req.csrfToken(),
        });
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error(err);
            return res.render('error', { message: 'An error occurred', error: err });
        }

        // Insert into database
        db.run(
            `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.render('register', {
                            error: 'Username or email already exists',
                            csrfToken: req.csrfToken(),
                        });
                    } else {
                        console.error(err);
                        return res.render('error', { message: 'An error occurred', error: err });
                    }
                }
                // Regenerate session to prevent session fixation
                req.session.regenerate((err) => {
                    if (err) {
                        console.error(err);
                        return res.render('error', { message: 'An error occurred', error: err });
                    }
                    req.session.user = { id: this.lastID, username };
                    res.redirect('/');
                });
            }
        );
    });
});

// Login Page
app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { error: null, csrfToken: req.csrfToken() });
});

// Handle Login
app.post('/login', csrfProtection, loginLimiter, (req, res) => {
    const { identifier, password } = req.body;

    // Validate input
    if (!identifier || !password) {
        return res.render('login', {
            error: 'Please provide both username/email and password.',
            csrfToken: req.csrfToken(),
        });
    }

    // Find user by username or email
    db.get(
        `SELECT * FROM users WHERE username = ? OR email = ?`,
        [identifier, identifier],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            if (user) {
                bcrypt.compare(password, user.password, (err, result) => {
                    if (err) {
                        console.error(err);
                        return res.render('error', { message: 'An error occurred', error: err });
                    }

                    if (result) {
                        // Regenerate session to prevent session fixation
                        req.session.regenerate((err) => {
                            if (err) {
                                console.error(err);
                                return res.render('error', { message: 'An error occurred', error: err });
                            }
                            req.session.user = { id: user.id, username: user.username };
                            res.redirect('/');
                        });
                    } else {
                        res.render('login', { error: 'Invalid credentials', csrfToken: req.csrfToken() });
                    }
                });
            } else {
                res.render('login', { error: 'Invalid credentials', csrfToken: req.csrfToken() });
            }
        }
    );
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
        }
        res.redirect('/');
    });
});

// Reset Password Page
app.get('/reset', csrfProtection, (req, res) => {
    res.render('reset', { error: null, message: null, csrfToken: req.csrfToken() });
});

// Handle Password Reset
app.post('/reset', csrfProtection, (req, res) => {
    const { email } = req.body;

    if (!validator.isEmail(email)) {
        return res.render('reset', {
            error: 'Invalid email address',
            message: null,
            csrfToken: req.csrfToken(),
        });
    }

    // Check if email exists
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) {
            console.error(err);
            return res.render('error', { message: 'An error occurred', error: err });
        }

        if (user) {
            // Generate a secure reset token
            const resetToken = crypto.randomBytes(32).toString('hex');
            const expires = new Date(Date.now() + 3600000); // 1 hour from now

            // Save the reset token and expiration in the database
            db.run(
                `UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?`,
                [resetToken, expires.toISOString(), email],
                (err) => {
                    if (err) {
                        console.error(err);
                        return res.render('error', { message: 'An error occurred', error: err });
                    }

                    // Send email (simulated)
                    console.log(
                        `Password reset link: http://localhost:3000/reset/${resetToken}`
                    );

                    res.render('reset', {
                        message:
                            'A reset link has been sent to your email (check console for link).',
                        error: null,
                        csrfToken: req.csrfToken(),
                    });
                }
            );
        } else {
            res.render('reset', {
                error: 'Email not found',
                message: null,
                csrfToken: req.csrfToken(),
            });
        }
    });
});

// New Password Page
app.get('/reset/:token', csrfProtection, (req, res) => {
    const { token } = req.params;

    db.get(
        `SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?`,
        [token, new Date().toISOString()],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            if (user) {
                res.render('new-password', {
                    error: null,
                    csrfToken: req.csrfToken(),
                    email: user.email,
                });
            } else {
                res.render('error', { message: 'Invalid or expired token', error: null });
            }
        }
    );
});

// Handle New Password Submission
app.post('/reset/:token', csrfProtection, (req, res) => {
    const { password, confirm_password } = req.body;
    const { token } = req.params;

    if (password !== confirm_password) {
        return res.render('new-password', {
            error: 'Passwords do not match',
            csrfToken: req.csrfToken(),
        });
    }

    if (
        !validator.isStrongPassword(password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
        })
    ) {
        return res.render('new-password', {
            error:
                'Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol.',
            csrfToken: req.csrfToken(),
        });
    }

    db.get(
        `SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?`,
        [token, new Date().toISOString()],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            if (user) {
                bcrypt.hash(password, 10, (err, hashedPassword) => {
                    if (err) {
                        console.error(err);
                        return res.render('error', { message: 'An error occurred', error: err });
                    }

                    // Update password and clear reset token
                    db.run(
                        `UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?`,
                        [hashedPassword, user.id],
                        (err) => {
                            if (err) {
                                console.error(err);
                                return res.render('error', { message: 'An error occurred', error: err });
                            }

                            res.redirect('/login');
                        }
                    );
                });
            } else {
                res.render('error', { message: 'Invalid or expired token', error: null });
            }
        }
    );
});

// Profile Page (Logged-in User)
app.get('/profile', csrfProtection, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const userId = req.session.user.id;

    db.get(
        `SELECT id, username, email, bio, avatar, created_at FROM users WHERE id = ?`,
        [userId],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            if (user) {
                // Fetch user's posts
                db.all(
                    `SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC`,
                    [userId],
                    (err, posts) => {
                        if (err) {
                            console.error(err);
                            return res.render('error', { message: 'An error occurred', error: err });
                        }

                        res.render('profile', {
                            user,
                            posts,
                            isOwner: true,
                            csrfToken: req.csrfToken(),
                        });
                    }
                );
            } else {
                req.session.destroy();
                res.redirect('/login');
            }
        }
    );
});

// Edit Profile Page
app.get('/profile/edit', csrfProtection, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    db.get(
        `SELECT id, username, email, bio, avatar FROM users WHERE id = ?`,
        [req.session.user.id],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            if (user) {
                res.render('edit-profile', {
                    user,
                    error: null,
                    csrfToken: req.csrfToken(),
                });
            } else {
                req.session.destroy();
                res.redirect('/login');
            }
        }
    );
});

// Handle Profile Update
app.post(
    '/profile/edit',
    upload.single('avatar'),
    csrfProtection,
    async (req, res) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }

        const { email, bio } = req.body;
        let avatarData = null;

        if (email && !validator.isEmail(email)) {
            return res.render('edit-profile', {
                user: req.body,
                error: 'Invalid email address.',
                csrfToken: req.csrfToken(),
            });
        }

        if (req.file) {
            try {
                const fileType = await FileType.fromBuffer(req.file.buffer);
                const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];

                if (!fileType || !allowedTypes.includes(fileType.mime)) {
                    return res.render('edit-profile', {
                        user: req.body,
                        error: 'Invalid file type. Only JPEG, PNG, and GIF are allowed.',
                        csrfToken: req.csrfToken(),
                    });
                }

                // Convert the image to a base64 string
                avatarData = req.file.buffer.toString('base64');
            } catch (err) {
                console.error(err);
                return res.render('edit-profile', {
                    user: req.body,
                    error: 'An error occurred while processing the file.',
                    csrfToken: req.csrfToken(),
                });
            }
        }

        // Update the user's profile in the database
        const params = [email, bio];
        let sql = `UPDATE users SET email = ?, bio = ?`;

        if (avatarData) {
            sql += `, avatar = ?`;
            params.push(avatarData);
        }

        sql += ` WHERE id = ?`;
        params.push(req.session.user.id);

        db.run(sql, params, function (err) {
            if (err) {
                console.error(err);
                res.render('edit-profile', {
                    user: req.body,
                    error: 'An error occurred while updating your profile.',
                    csrfToken: req.csrfToken(),
                });
            } else {
                res.redirect('/profile');
            }
        });
    }
);

// View User Profile and Posts
app.get('/user/:id', csrfProtection, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const userId = req.params.id;

    db.get(
        `SELECT id, username, bio, avatar, created_at FROM users WHERE id = ?`,
        [userId],
        (err, user) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            if (user) {
                // Fetch user's posts
                db.all(
                    `SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC`,
                    [userId],
                    (err, posts) => {
                        if (err) {
                            console.error(err);
                            return res.render('error', { message: 'An error occurred', error: err });
                        }

                        res.render('profile', {
                            user,
                            posts,
                            isOwner: req.session.user.id == userId,
                            csrfToken: req.csrfToken(),
                        });
                    }
                );
            } else {
                res.status(404).render('error', { message: 'User not found', error: null });
            }
        }
    );
});

// Member List Page
app.get('/members', csrfProtection, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    db.all(
        `SELECT id, username FROM users ORDER BY username`,
        [],
        (err, members) => {
            if (err) {
                console.error(err);
                return res.render('error', { message: 'An error occurred', error: err });
            }

            res.render('memberlist', { members, csrfToken: req.csrfToken() });
        }
    );
});

// Search Results Page
app.get('/search', csrfProtection, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const query = req.query.q;
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    if (!query) {
        return res.render('search', {
            posts: [],
            query: '',
            error: null,
            currentPage: 1,
            totalPages: 0,
            csrfToken: req.csrfToken(),
        });
    }

    const sanitizedQuery = validator.escape(query);

    // Count total matching posts
    db.get(
        `SELECT COUNT(*) AS count FROM posts WHERE content LIKE '%' || ? || '%'`,
        [sanitizedQuery],
        (err, result) => {
            if (err) {
                console.error(err);
                return res.render('search', {
                    posts: [],
                    query: sanitizedQuery,
                    error: 'An error occurred while searching.',
                    currentPage: 1,
                    totalPages: 0,
                    csrfToken: req.csrfToken(),
                });
            }
            const totalPosts = result.count;
            const totalPages = Math.ceil(totalPosts / limit);

            // Fetch matching posts for current page
            db.all(
                `SELECT posts.*, users.username, users.avatar
         FROM posts
         JOIN users ON posts.user_id = users.id
         WHERE posts.content LIKE '%' || ? || '%'
         ORDER BY posts.created_at DESC
         LIMIT ? OFFSET ?`,
                [sanitizedQuery, limit, offset],
                (err, posts) => {
                    if (err) {
                        console.error(err);
                        return res.render('search', {
                            posts: [],
                            query: sanitizedQuery,
                            error: 'An error occurred while searching.',
                            currentPage: 1,
                            totalPages: 0,
                            csrfToken: req.csrfToken(),
                        });
                    }
                    res.render('search', {
                        posts,
                        query: sanitizedQuery,
                        error: null,
                        currentPage: page,
                        totalPages,
                        csrfToken: req.csrfToken(),
                    });
                }
            );
        }
    );
});

// Start the server
app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});