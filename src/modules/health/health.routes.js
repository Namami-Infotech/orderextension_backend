const express = require('express');
const { asyncHandler } = require('../../utils/util');
const healthController = require('./health.controller');

const router = express.Router();

router.get('/health', asyncHandler(healthController.checkHealth));

module.exports = router;
