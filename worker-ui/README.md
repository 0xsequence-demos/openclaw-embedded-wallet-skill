# Email Embedded Wallet Boilerplate
Starter email based authentication for Sequence Embedded Wallet boilerplate that uses [Sequence Embedded Wallet](https://docs.sequence.xyz/solutions/wallets/embedded-wallet/overview) with React.

## Quickstart

Copy `.env.example` to `.env` and fill with your project information. To test things out, you can use the pre-provided keys in the `.env.example` file:

```
cp .env.example .env
```

Or, just install and run and the `postinstall` will take care of copying default keys:

```js
pnpm install && pnpm dev
```

The app will start on `localhost:4444`

To provide your own keys from [Sequence Builder](https://sequence.build/), simply edit the `.env` file accordingly.
