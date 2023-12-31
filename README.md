# Simple Registration

"Simple Registration" is a lightweight HTTP server developed in JavaScript, built on the Express framework, and features a Vue 3 frontend. Its core functionality is designed to simplify the process of creating user registration and login forms.

## Prerequisites

To begin working with this project, you need to have Node.js installed on your machine. You can download it from the official Node.js website (https://nodejs.org/en/download/).

Additionally, you must set up and configure a MySQL database, including specifying connection parameters like the host, username, password, and database name.
There is a database dump file included in the project, you can streamline the database setup process. First, create an empty MySQL database where you want to import the data. Then, using the MySQL command-line interface or a tool like phpMyAdmin, you can simply use the SOURCE command to import the data from the provided dump file into your newly created database. This process will populate the database with the necessary tables and data, making it ready for your project without the need for manual table creation and data insertion. It's a convenient way to set up the database quickly and efficiently.
This will allow your application to interact with the MySQL database efficiently. If you don't already have MySQL installed, you can download it from the official MySQL website (https://dev.mysql.com/downloads/installer/). 


## Getting Started

To begin working on this project, ensure you've already installed Node.js and configured your MySQL database. Once you've taken care of these prerequisites, follow these steps to get up and running:

1. Fork and clone this repository to your local machine.
1. Navigate to the root directory of the project in your terminal.
1. Create a local environment configuration file by executing `cp .env.sample .env` and update the database settings in the newly created `.env` file to match your MySQL database configuration.
1. Run `npm install` to fetch and install all the required project dependencies.
1. Start the server by running `npm start`, which will launch it on port 3000.
1. Open your web browser and go to [http://localhost:3000/](http://localhost:3000/) to access and use the application.


## Acknowledgments

- [Express](https://expressjs.com/) for the web framework.
- [Node.js](https://nodejs.org/en/) for the JavaScript runtime.
- [NPM](https://www.npmjs.com/) for the package manager.
- [Dotenv](https://www.npmjs.com/package/dotenv) for the environment variables.
- [Bcrypt](https://www.npmjs.com/package/bcrypt) for the password hashing.
- [Mysql2](https://www.npmjs.com/package/mysql2) for MySQL client and the database.
- [UUID](https://www.npmjs.com/package/uuid) for generating unique identifiers.