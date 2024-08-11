module.exports = {
    development: {
      client: 'pg', // Change to 'mysql' or 'sqlite3' as needed
      connection: {
        host: '127.0.0.1',
        user: 'postgres',
        password: 'thanos',
        database: 'auth_db'
      }
    },

    production: {
        client: 'pg', // Change to 'mysql' or 'sqlite3' as needed
        connection: {
          host: '127.0.0.1',
          user: 'postgres',
          password: 'thanos',
          database: 'auth_db'
        }
      }
  };