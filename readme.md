# Node.js Authentication Backend

This Node.js backend project provides authentication functionalities, including user registration, login, logout, forgot password, updating profile, and Google OAuth integration.

## Features

- **User Registration:** Users can register with their first name, last name, email, and password.

- **User Login:** Registered users can log in using their email and password.

- **User Logout:** Users can log out to terminate their authenticated session.

- **Forgot Password:** Users can reset their password by initiating a forgot password request.

- **Update Profile:** Authenticated users can update their profile information.

- **Google OAuth Integration:** Users can log in or register using their Google account.

## Technologies Used

- Node.js
- Express.js
- MongoDB (or your preferred database)
- Mongoose (or your preferred ODM/ORM)
- bcryptjs for password hashing
- JSON Web Tokens (JWT) for authentication
- Passport.js for Google OAuth integration