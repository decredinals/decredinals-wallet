# Decredinals Wallet — dApp Integration Guide

Decredinals Wallet is a **non-custodial browser extension wallet for Decred** that allows websites (dApps) to connect to user wallets, read balances, and request transactions — similar to MetaMask, but built natively for the Decred ecosystem.

This document describes **how to integrate Decredinals Wallet into your website or dApp**.

---

## Features for dApps

- Non-custodial (keys never leave the extension)
- Per-site permissions (origin-based)
- Access wallet address
- Read DCR balance
- Request & sign transactions via confirmation popup
- Async request / response API
- Simple provider model (`window.decred`)

---

## Wallet Provider Injection

When the Decredinals Wallet extension is installed, it injects a provider into every webpage:

```js
window.decred
// alias
window.dcrWallet
```

The provider exposes a single method:

```js
provider.request({ method, params })
```

Once injected, the wallet dispatches the event:

```js
window.dispatchEvent(new Event("decred#initialized"));
```

Your dApp should wait for this event before using the provider.

---

## Detecting the Wallet

```js
function getDecredProvider() {
  return window.decred || window.dcrWallet || null;
}

async function waitForDecredWallet(timeout = 1500) {
  const existing = getDecredProvider();
  if (existing) return existing;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      window.removeEventListener("decred#initialized", onInit);
      reject(new Error("Decredinals Wallet not found"));
    }, timeout);

    function onInit() {
      clearTimeout(timer);
      window.removeEventListener("decred#initialized", onInit);
      resolve(getDecredProvider());
    }

    window.addEventListener("decred#initialized", onInit);
  });
}
```

---

## Connecting a Website (Wallet Connect)

### Method: `dcr_requestAccounts`

Requests user approval to connect the current site to Decredinals Wallet.

- Opens a **Connect popup** on first request
- Permissions are stored per `origin`
- Returns active wallet information

```js
const dcr = await waitForDecredWallet();

const account = await dcr.request({
  method: "dcr_requestAccounts"
});

console.log(account);
/*
{
  address: "Ds...",
  balanceDcr: 12.3456789,
  balanceAtoms: 1234567890
}
*/
```

---

## Getting Wallet Balance

### Method: `dcr_getBalance`

Returns the current balance of the active wallet.

```js
const balance = await dcr.request({
  method: "dcr_getBalance"
});
```

---

## Sending a Transaction

### Method: `dcr_sendTransaction`

Requests the wallet to build, sign, and broadcast a transaction.

```js
const result = await dcr.request({
  method: "dcr_sendTransaction",
  params: {
    to: "DsExampleAddress...",
    amountDcr: 1.25
  }
});

console.log("TXID:", result.txid);
```

---

## Security Model

- Permissions are **origin-based**
- No private keys or WIFs are ever exposed to websites
- All signing happens **inside the extension**
- Every transaction requires **explicit user confirmation**

---

## Architecture Overview

```
Website (dApp)
   │
   │ window.decred.request()
   ▼
In-page Provider (inpage.js)
   │ postMessage
   ▼
Content Script (content.js)
   │ chrome.runtime.sendMessage
   ▼
Background / Service Worker (sw.js)
   │
   ├─ connect.html / connect.js
   └─ confirm.html / confirm.js
```




