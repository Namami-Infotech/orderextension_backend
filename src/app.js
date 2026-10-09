const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const config = require('./config');
const { globalLimiter } = require('./middlewares/rateLimiter.middleware');
const { notFoundHandler, errorHandler } = require('./middlewares/error.middleware');
const routes = require('./routes');

const app = express();

// Trust proxy settings
app.set('trust proxy', config.trustProxy);

// Security & Parsing Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// Global rate limiting (every endpoint, per IP)
app.use(globalLimiter);

// API Routes
app.use(routes);

// 404 and Error handling
app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
