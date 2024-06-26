# MERn_AUTHOR (An authentication npm package)

A comprehensive authentication service for Node.js applications, providing methods for user login, signup, logout, authentication, and authorization.

## Installation

Install the package using npm:

```bash
npm install your-package-name
```

## Usage

### Setup

First, import and instantiate the AuthService class with the required parameters:

```bash
const AuthService = require('your-package-name');
const UserModel = require('./models/User'); // Replace with your actual user model

const jwtSecret = 'your_jwt_secret';
const jwtExpiry = '30d';
const env = process.env.NODE_ENV || 'development';

const authService = new AuthService(UserModel, jwtSecret, jwtExpiry, env);
```

## Methods

### Login

Handles user login and generates a JWT token.

```bash
app.post('/login', authService.login);
```

### Signup

Handles user registration and generates a JWT token.

```bash
app.post('/signup', authService.signUp);
```

### Logout

Clears the JWT token.

```
app.post('/logout', authService.logout);
```

### IsAuthenticated

Middleware to check if the user is authenticated.

```
app.use(authService.isAuthenticated);
```

### IsAuthorized

Middleware to check if the user is authorized to access a route based on roles.

```
app.use(authService.isAuthorized('admin', 'moderator'));
```

## Example

Here's a complete example of how to use AuthService in an Express application:

```
const express = require('express');
const cookieParser = require('cookie-parser');
const AuthService = require('your-package-name');
const UserModel = require('./models/User'); // Replace with your actual user model

const app = express();
app.use(express.json());
app.use(cookieParser());

const jwtSecret = 'your_jwt_secret';
const jwtExpiry = '30d';
const env = process.env.NODE_ENV || 'development';

const authService = new AuthService(UserModel, jwtSecret, jwtExpiry, env);

app.post('/login', authService.login);
app.post('/signup', authService.signUp);
app.post('/logout', authService.logout);

app.use(authService.isAuthenticated);

app.get('/protected', authService.isAuthorized('admin'), (req, res) => {
  res.send('This is a protected route');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```

## Configuration

When creating an instance of `AuthService`, you need to provide the following parameters:

- `usermodel`: Your user model (Mongoose model)
- `jwtSecret`: A secret key for signing JWT tokens
- `jwtExpiry`: Token expiration time (default is `30d`)
- `env`: Environment (default is `development`)

### License

This project is licensed under the MIT License.
