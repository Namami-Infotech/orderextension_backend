const app = require('./app');
const config = require('./config');
const { pool, query } = require('./config/db');

async function startServer() {
  try {
    // Verify DB connection
    await query('SELECT 1');
    console.log('Database connected successfully.');

    const server = app.listen(config.port, config.host, () => {
      console.log(`License server listening on ${config.host}:${config.port}`);
    });

    const stop = () => {
      console.log('Shutting down server...');
      server.close(() => {
        pool.end().then(() => {
          console.log('Server and database pool closed.');
          process.exit(0);
        });
      });
    };

    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
  } catch (error) {
    console.error('Cannot connect to the database:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = app;
