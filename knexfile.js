require('dotenv').config();

module.exports = {
    development: {
      client: 'pg',
      connection: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'thanos',
        database: process.env.DB_NAME || 'auth_db',
        port: process.env.DB_PORT || 5432
      }
    },

    production: {
      client: 'pg',
      connection: process.env.DB_CONNECTION_STRING // Connection URL
    }
};