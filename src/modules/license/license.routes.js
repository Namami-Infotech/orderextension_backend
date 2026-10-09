const express = require('express');
const { strictLimiter } = require('../../middlewares/rateLimiter.middleware');
const { requireToken } = require('../../middlewares/auth.middleware');
const { asyncHandler } = require('../../utils/util');
const licenseController = require('./license.controller');

const router = express.Router();

router.post('/activate', strictLimiter, asyncHandler(licenseController.activate));
router.post('/challenge', strictLimiter, asyncHandler(licenseController.challenge));
router.post('/login', strictLimiter, asyncHandler(licenseController.login));
router.post('/ping', requireToken, asyncHandler(licenseController.ping));
router.post('/logout', requireToken, asyncHandler(licenseController.logout));

module.exports = router;
