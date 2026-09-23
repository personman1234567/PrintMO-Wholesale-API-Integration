# PrintMO-Wholesale-API-Integration

## Read-only S&S inventory gateway

`GET /order-manager/v1/supplier/ss/inventory?skus=SKU1,SKU2` serves the separate inventory observation Worker. It uses the existing `X-Order-Manager-Key` authentication and the gateway's server-held `SS_ACCOUNT_NUMBER` and `SS_API_KEY`. Requests must contain 1–25 distinct S&S SKUs. The response contains only `observedAt` and `items` with `sku`, `warehouseAbbr`, and nonnegative integer `qty`; it is marked `Cache-Control: no-store`. Missing supplier rows remain missing, and upstream errors never become zero stock.

The route makes only a bounded GET to S&S. It does not update Shopify, place supplier orders, or use Redis. `observedAt` is the gateway fetch time, not an S&S source timestamp. Run `npm test` before deploying this shared service; it includes the existing phase-two checks and focused inventory-route checks. After deployment, verify the existing order routes and make one authenticated inventory read before enabling the separate Worker's dry-run schedule. The route code alone does not deploy the service.
