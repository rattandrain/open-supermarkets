// Run inside the built image: checks the in-process HTTP allowlist.
const { assertAllowed } = require('/app/dist/hardening/ocado-allowlist.js');
const ok = [
  ['GET', 'https://www.ocado.com/'],
  ['GET', 'https://www.ocado.com/search?q=lemons'],
  ['GET', 'https://www.ocado.com/favorites'],
  ['GET', 'https://www.ocado.com/api/cart/v1/carts/active?cartProductSorting=CATEGORIES'],
  ['POST', 'https://www.ocado.com/api/cart/v1/carts/active/apply-quantity?cartProductSorting=CATEGORIES'],
  ['PUT', 'https://www.ocado.com/api/webproductpagews/v6/products'],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders' }],
  ['GET', 'https://www.ocado.com/api/order/v6/orders/abc-123'],
];
const bad = [
  ['GET', 'https://www.ocado.com/checkout'],
  ['POST', 'https://www.ocado.com/api/ecomslots/v2/slots'],
  ['GET', 'https://www.ocado.com/login'],
  ['GET', 'https://www.ocado.com/account/payment-cards'],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'PlaceOrder' }],
  ['GET', 'https://www.ocado.com/search/../checkout'],
  ['GET', 'https://www.ocado.com/search%2F..%2Fcheckout'],
  ['GET', 'https://evil.example/search'],
  ['GET', 'http://www.ocado.com/search'],
  ['GET', 'https://www.ocado.com:8443/search'],
  ['GET', 'https://www.ocado.com.evil.example/search'],
  ['DELETE', 'https://www.ocado.com/api/cart/v1/carts/active'],
];
let failures = 0;
for (const [m, u, d] of ok) { try { assertAllowed(m, u, d); console.log('allowed  OK  ', m, u); } catch (e) { failures++; console.log('FAIL allowed', m, u, e.message); } }
for (const [m, u, d] of bad) { try { assertAllowed(m, u, d); failures++; console.log('FAIL blocked', m, u); } catch { console.log('blocked  OK  ', m, u); } }
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURES`);
process.exit(failures ? 1 : 0);
