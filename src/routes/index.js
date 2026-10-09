const express = require('express');
const healthRoutes = require('../modules/health/health.routes');
const licenseRoutes = require('../modules/license/license.routes');

const router = express.Router();

// Mount module routes
router.use('/', healthRoutes);
router.use('/', licenseRoutes);

module.exports = router;
