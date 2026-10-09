// Settings the extension receives ONLY after a valid login or ping.
// Put here the parts of your extension that you want to be able to change without shipping
// a new version, and that make a copied extension useless without this server.

function getScanConfig(license) {
  return {
    station: license.station_code,
    batchSize: 25,          // how many order IDs per batch
    delayMs: 400,           // pause between requests
    maxIdsPerRun: 2000,     // per-scan safety limit
    endpoints: {
      // example only: fill with the real paths your extension calls
      // orderSummary: '/path/to/order/summary',
      // orderTabs: '/path/to/order/tabs',
    },
    columns: {
      // example only: which fields go in which sheet / order
      // Orders: ['orderId', 'status', 'buyerName'],
      // History: ['orderId', 'event', 'time'],
    },
  };
}

module.exports = { getScanConfig };
