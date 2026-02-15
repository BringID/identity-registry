# BringID App Manager — Specs

## Overview

A web dashboard for third-party app developers to self-manage their BringID integration. App admins connect their wallet and manage their app's settings, custom scoring, and lifecycle — all via direct contract calls (no backend needed).

**Target users:** App developers who register an app on the CredentialRegistry and want to configure scoring, recovery, and admin settings.

**Non-goals (v1):** Registry owner operations (creating credential groups, managing trusted verifiers), credential registration/renewal, proof submission. These are BringID internal operations and out of scope.

---

## Contract Surface

All interactions go to two contracts on Base (mainnet 8453 / Sepolia 84532):

### CredentialRegistry (`0x4CeA320D9b08A3a32cfD55360E0fc2137542478d`)

| Function | Access | Description |
|---|---|---|
| `registerApp(uint256 recoveryTimelock)` | Public | Register new app, caller becomes admin. Returns `appId`. |
| `suspendApp(uint256 appId)` | App admin | Suspend app (blocks registrations + proofs). |
| `activateApp(uint256 appId)` | App admin | Reactivate suspended app. |
| `setAppRecoveryTimelock(uint256 appId, uint256 timelock)` | App admin | Set recovery timelock (0 = disabled). |
| `setAppAdmin(uint256 appId, address newAdmin)` | App admin | Transfer admin to new address. |
| `setAppScorer(uint256 appId, address scorer)` | App admin | Point app to a custom scorer contract. |
| `apps(uint256 appId)` | View | Returns `(status, recoveryTimelock, admin, scorer)`. |
| `appIsActive(uint256 appId)` | View | Returns bool. |
| `defaultScorer()` | View | Address of the DefaultScorer. |
| `nextAppId()` | View | Next auto-increment ID (use to enumerate). |
| `credentialGroups(uint256 id)` | View | Returns `(status, validityDuration, familyId)`. |
| `getCredentialGroupIds()` | View | Returns all registered credential group IDs. |

### DefaultScorer (`0xcE4A14a929FfF47df30216f4C8fa8907825F494F`)

Read-only from the dashboard's perspective (only BringID owner can write):

| Function | Access | Description |
|---|---|---|
| `getScore(uint256 credentialGroupId)` | View | Score for one group. |
| `getScores(uint256[] credentialGroupIds)` | View | Scores for multiple groups. |
| `getAllScores()` | View | All group IDs + scores. |

### ScorerFactory (`0x7cE2d6AdA1a9ba7B03b1F6d0C84EC01c3005cCa9`)

Deploys DefaultScorer instances owned by the caller. Same address on both chains.

| Function | Access | Description |
|---|---|---|
| `create()` | Public | Deploy a new DefaultScorer owned by msg.sender. Returns address. |

### Custom Scorer (IScorer interface)

Apps can deploy their own scorer implementing `IScorer`:

```solidity
interface IScorer {
    function getScore(uint256 credentialGroupId) external view returns (uint256);
    function getScores(uint256[] calldata credentialGroupIds) external view returns (uint256[] memory);
    function getAllScores() external view returns (uint256[] memory, uint256[] memory);
}
```

The dashboard should help app admins deploy a custom scorer or point to an existing one.

---

## Pages / Features

### 1. Connect Wallet

- Standard wallet connect (WalletConnect / injected provider).
- Support Base mainnet + Base Sepolia. Network switcher.
- Connected address shown in header. All admin-gated actions derive from the connected wallet.

### 2. Register App

- Single form: **Recovery Timelock** input (seconds, with human-readable preview like "2 days"). Default: 0 (disabled).
- Calls `registerApp(recoveryTimelock)`.
- On success: show the returned `appId`, prompt to save it.
- Link to the new app's settings page.

### 3. My Apps (list)

- Enumerate apps where `apps[appId].admin == connectedAddress`.
  - Since there's no on-chain enumeration by admin, index via `AppRegistered` events filtered by `admin == connectedAddress`, plus `AppAdminTransferred` events (incoming/outgoing).
- Each card shows: **App ID**, **Status** (Active/Suspended), **Scorer** address (with label "Default" if it matches `defaultScorer()`), **Recovery Timelock** (human-readable).
- Click through to app detail.

### 4. App Detail / Settings

For an app where connected wallet is admin:

#### 4a. Status Management
- **Suspend** button (if active) — calls `suspendApp(appId)`.
- **Activate** button (if suspended) — calls `activateApp(appId)`.
- Show current status prominently.

#### 4b. Recovery Timelock
- Current value displayed in human-readable form.
- Edit field: input seconds, preview as "X hours / X days".
- Calls `setAppRecoveryTimelock(appId, newTimelock)`.
- Note: setting to 0 disables recovery for the app.

#### 4c. Admin Transfer
- Input field for new admin address (with ENS resolution if available).
- Warning: "This is irreversible. You will lose admin access."
- Confirmation dialog.
- Calls `setAppAdmin(appId, newAdmin)`.

#### 4d. Scorer Configuration
- Show current scorer address.
- Label as "Default (BringID)" if matches `defaultScorer()`.
- Two options:
  1. **Use Default Scorer** — calls `setAppScorer(appId, defaultScorer)`.
  2. **Use Custom Scorer** — input address, validate via `getAllScores()` try-call, then call `setAppScorer(appId, address)`. Show error if validation fails.
- Link to "Deploy Custom Scorer" (see below).

### 5. Score Explorer

Read-only view of the current scoring landscape:

- Table of all credential groups (from `getCredentialGroupIds()`):
  - **ID**, **Status** (Active/Suspended), **Validity Duration** (human-readable), **Family ID**, **Default Score** (from DefaultScorer).
- If the app has a custom scorer, show a second column with the app's custom scores alongside the defaults for comparison.

### 6. Deploy Custom Scorer

Guided flow for app admins to deploy their own scorer via the on-chain `ScorerFactory`:

- Display the list of credential groups + default scores for reference.
- Step 1: Call `ScorerFactory.create()` — single tx, connected wallet becomes scorer owner.
- Step 2: On success, auto-call `setAppScorer(appId, newScorerAddress)` to wire it up.
- Step 3: Redirect to "Manage Custom Scores" to set initial scores.
- If admin already has a custom scorer deployed (check `ScorerCreated` events), offer to reuse it.

### 7. Manage Custom Scores

If the app's scorer is a contract owned by the connected wallet (not the DefaultScorer):

- Table: credential group ID, current score, editable field.
- Batch update via `setScores(uint256[] ids, uint256[] scores)` (if the scorer supports it).
- Single update via `setScore(uint256 id, uint256 score)`.

---

## Tech Stack

| Layer | Choice | Rationale |
|---|---|---|
| Framework | Next.js (App Router) | Standard for web3 dashboards, SSG-capable |
| Wallet | wagmi + viem + ConnectKit (or RainbowKit) | De facto standard, Base chain support |
| Styling | Tailwind CSS | Fast iteration, no component library lock-in |
| Contract ABIs | Copy from `identity-registry` build artifacts (`out/`) | Typed via wagmi CLI codegen |
| Chain config | Base mainnet (8453) + Base Sepolia (84532) | Match the deployed contracts |
| Hosting | Vercel | Zero-config Next.js deploys |
| Event indexing | viem `getLogs` with filters | No subgraph needed for v1 — event volume is low |

No backend or database. Everything reads from chain state and events.

---

## Contract ABIs Needed

From the `identity-registry` `out/` directory after `forge build`:

- `out/CredentialRegistry.sol/CredentialRegistry.json` — full ABI
- `out/DefaultScorer.sol/DefaultScorer.json` — full ABI

Extract only the `abi` field from each JSON. Alternatively, generate minimal ABIs from the interfaces (`ICredentialRegistry.sol`, `IScorer.sol`).

---

## Custom Scorer: Factory Contract

Deploy a `ScorerFactory` on-chain (same addresses on Base mainnet + Sepolia). The factory creates `DefaultScorer` instances owned by the caller. `DefaultScorer` accepts an `owner_` constructor param, so it serves as both the global default (owned by BringID) and per-app custom scorers (owned by the app admin).

### ScorerFactory.sol

```solidity
contract ScorerFactory {
    event ScorerCreated(address indexed scorer, address indexed owner);

    /// @notice Deploy a new DefaultScorer owned by msg.sender.
    function create() external returns (address scorer) {
        DefaultScorer s = new DefaultScorer(msg.sender);
        emit ScorerCreated(address(s), msg.sender);
        return address(s);
    }
}
```

No separate `CustomScorer` contract — `DefaultScorer` handles both use cases.

**Dashboard flow (Deploy Custom Scorer page):**
1. Call `ScorerFactory.create()` — one tx, caller becomes owner.
2. On success, auto-call `setAppScorer(appId, newScorerAddress)`.
3. Redirect to "Manage Custom Scores" to set initial scores.

**Benefits over raw bytecode deploy:** discoverable (index `ScorerCreated` events), simpler UX (single function call vs raw deploy), verifiable on block explorer.

The `ScorerFactory` contract lives in this repo (`identity-registry`) under `src/scoring/` and is deployed alongside the other contracts.

---

## Event Indexing

Events needed for the "My Apps" list and activity feeds:

```
AppRegistered(appId, admin, recoveryTimelock)         — index by admin
AppAdminTransferred(appId, oldAdmin, newAdmin)         — track admin changes
AppSuspended(appId)                                    — status changes
AppActivated(appId)                                    — status changes
AppScorerSet(appId, scorer)                            — scorer changes
AppRecoveryTimelockSet(appId, timelock)                — config changes
```

Query strategy:
1. `AppRegistered` where `admin == connectedAddress` — apps I created.
2. `AppAdminTransferred` where `newAdmin == connectedAddress` — apps transferred to me.
3. `AppAdminTransferred` where `oldAdmin == connectedAddress` — apps I transferred away (exclude from list).
4. For each candidate appId, verify current admin via `apps(appId)` on-chain (events may be stale if admin was transferred multiple times).

---

## Error Handling

Map contract revert strings to user-friendly messages:

| Revert | User Message |
|---|---|
| `BID::not app admin` | You are not the admin of this app. |
| `BID::app not active` | This app is currently suspended. |
| `BID::app not suspended` | This app is already active. |

---

## Decisions

1. **Factory contract for CustomScorer.** A `ScorerFactory` is deployed on-chain. Dashboard calls `factory.create()` — one tx, caller becomes owner. Scorers are discoverable via `ScorerCreated` events. See "Custom Scorer: Factory Contract" section above.

2. **Admin-only for v1.** No public app lookup by ID. The dashboard only shows apps where the connected wallet is the current admin. Public app detail can be added later.

3. **Scorer validation before `setAppScorer`.** Before submitting the transaction, the dashboard calls `getAllScores()` on the target address. If the call reverts or returns malformed data, show an error: "This address does not implement the IScorer interface." This prevents admins from accidentally pointing to a broken contract. The validation is a client-side view call only — no gas cost.
