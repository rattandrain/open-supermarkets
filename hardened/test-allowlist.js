// Run inside the built image: checks the in-process HTTP allowlist.
const { assertAllowed, COMPLETED_ORDERS_QUERY: Q } = require(process.env.ALLOWLIST_MODULE || '/app/dist/hardening/ocado-allowlist.js');
const ok = [
  ['GET', 'https://www.ocado.com/'],
  ['GET', 'https://www.ocado.com/search?q=lemons'],
  ['GET', 'https://www.ocado.com/favorites'],
  ['GET', 'https://www.ocado.com/api/cart/v1/carts/active?cartProductSorting=CATEGORIES'],
  ['POST', 'https://www.ocado.com/api/cart/v1/carts/active/apply-quantity?cartProductSorting=CATEGORIES'],
  ['PUT', 'https://www.ocado.com/api/webproductpagews/v6/products'],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders', query: Q, variables: { first: 10 } }],
  ['POST', 'https://www.ocado.com/graphql', JSON.stringify({ operationName: 'GetCompletedOrders', query: Q, variables: { first: 10, after: 'abc' } })],
  ['GET', 'https://www.ocado.com/api/order/v6/orders/abc-123'],
];
const bad = [
  ['GET', 'https://www.ocado.com/checkout'],
  ['POST', 'https://www.ocado.com/api/ecomslots/v2/slots'],
  ['GET', 'https://www.ocado.com/login'],
  ['GET', 'https://www.ocado.com/account/payment-cards'],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'PlaceOrder' }],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders' }],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders', query: 'mutation { placeOrder }', variables: { first: 10 } }],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders', query: Q + ' mutation X { a }', variables: { first: 10 } }],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders', query: Q, variables: { first: 10, extra: 1 } }],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders', query: Q, variables: { first: 999 } }],
  ['POST', 'https://www.ocado.com/graphql', { operationName: 'GetCompletedOrders', query: Q, variables: { first: 10 }, extensions: {} }],
  ['POST', 'https://www.ocado.com/graphql', [{ operationName: 'GetCompletedOrders', query: Q, variables: { first: 10 } }]],
  ['GET', 'https://www.ocado.com/graphql?query=mutation'],
  ['GET', 'https://www.ocado.com/SEARCH'],
  ['GET', 'https://www.ocado.com/search;jsessionid=x'],
  ['GET', 'https://www.ocado.com/search%2e%2e/checkout'],
  ['GET', 'https://www.ocado.com/%2E%2E/checkout'],
  ['GET', 'https://www.ocado.com/search\\..\\checkout'],
  ['GET', 'https://www.ocado.com//checkout'],
  ['GET', 'https://user:pw@www.ocado.com/search'],
  ['GET', 'https://WWW.OCADO.COM./search'],
  ['GET', 'https://www.ocado.com/api/order/v6/orders/../../checkout'],
  ['GET', 'https://www.ocado.com/api/cart/v1/carts/active/checkout'],
  ['PUT', 'https://www.ocado.com/api/cart/v1/carts/active'],
  ['GET', 'https://www.ocado.com/api/recurringshopping/v2/web/definitions'],
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
