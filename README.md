# Decredinals Wallet

Decredinals Wallet is a non-custodial wallet for the Decred blockchain, designed to make it easy to create, manage, and use multiple Decred wallets.

Decredinals wallet allows users to:
- create and manage multiple Decred wallets,
- send and receive DCR,
- view balances and transaction history,
- securely manage keys locally without exposing private data.

The wallet is developed as the foundation for future Decredinals protocol support and inscription-related functionality.


---

## Decredinals Protocol

Inscriptions protocol layer enabling on-chain assets, indexing, wallets and marketplaces — powered by Decred.

**Learn more**

**Links**
- Website: https://decredinals.com  
- Documentation: https://docs.decredinals.com  
- Decredinals Web Wallet: https://wallet.decredinals.com
- Decredinals Wallet Chrome Webstore: https://chromewebstore.google.com/detail/decredinals-wallet/bhhacjnlllojmjfdikdfjicllpdkgklg   
- Twitter / X: https://x.com/decredinals  
- Telegram: https://t.me/decredinals

---

## Core Principles

### Non-custodial 
Private keys, seeds and signing operations are handled locally on the user’s device.


### Explicit API safety guarantees

The wallet API acts as a read-only blockchain data provider and transaction-building helper, handling balances, UTXOs, and transaction history.

Private keys and signing operations never leave the client.



### Open and verifiable
All code in this repository is released under the **ISC License** and intended for public audit and reuse.

---

## Repository Structure

```
decredinals-wallet/
├── web-wallet/          # Web-based non-custodial wallet UI
├── wallet-api/          # Wallet API and backend services
├── wallet-extension/    # Browser extension wallet (Chromium-based)
└── README.md
```

---

## Components

### 1. Decredinals Web Wallet (`/web-wallet`)

A web-based non-custodial wallet interface that supports:
- wallet creation and import,
- management of multiple wallets with easy switching,
- sending and receiving DCR,
- viewing balances and transaction history,
- optional connection to the Decredinals browser extension.
  
Try Decredinals Web Wallet - https://wallet.decredinals.com  


---

### 2. Decredinals Wallet API (`/wallet-api`)

The wallet API provides blockchain access and helper services for Decredinals wallet interfaces.

It is designed as a stateless, non-custodial backend that supplies blockchain data and assists with unsigned transaction construction.

#### Responsibilities
- blockchain data access (UTXOs, balances, transaction history),
- network and protocol metadata.

#### Data source
The API relies on Decred’s public block explorer infrastructure:

```
https://dcrdata.decred.org

```

This ensures:
- transparent and verifiable blockchain data,
- no trusted backend custody,
- compatibility with existing Decred infrastructure.

#### Security model
- no private keys, seed phrases or sensitive key material are ever accepted or stored,
- all cryptographic signing is performed locally by the wallet or browser extension.

---

### 3. Decredinals Wallet Extension (`/wallet-extension`)

A Chromium-based browser extension wallet that mirrors the core functionality of the web wallet in a compact extension format.
Chrome Web Store - https://chromewebstore.google.com/detail/decredinals-wallet/bhhacjnlllojmjfdikdfjicllpdkgklg

Features:
- wallet creation and import,
- management of multiple wallets with easy switching,
- sending and receiving DCR,
- viewing balances and transaction history,
- foundation for future dApp and protocol integrations.

---

## Browser Extension Installation

• Directly from the Chrome Web Store - https://chromewebstore.google.com/detail/decredinals-wallet/bhhacjnlllojmjfdikdfjicllpdkgklg
• Or manually via GitHub Releases


### Installation Steps from GitHub Releases

1. Open the **Releases** section of this repository - https://github.com/decredinals/decredinals-wallet/releases/tag/v0.0.1
2. Download the latest archive:
   ```
   decredinals-wallet-extension-<version>.zip
   ```
3. Extract the archive to a local directory.
4. Open a Chromium-based browser and navigate to:
   ```
   chrome://extensions
   ```
5. Enable **Developer mode**.
6. Click **Load unpacked**.
7. Select the extracted `wallet-extension` folder.

---

## License

All code in this repository is released under the **ISC License**.

This includes the web wallet, wallet API, browser extension and all supporting tooling.

---

## Status

This repository represents an early public release of the Decredinals Wallet infrastructure.
Future protocol features and application-layer releases, such as Decredinals inscriptions, auctions, GameFi integrations, and prediction markets, are expected to be delivered as separate repositories or future releases as development progresses.


---

## Disclaimer
This software is provided as-is for use, testing, and public review.

Users are responsible for understanding the software, securing their own keys and funds, and making informed usage decisions.

