# Credential Groups & Default Scoring

## 1. Credential Groups

| Credential | Group | Family | Validity | Description |
|---|---|---|---|---|
| **Farcaster** | Low | 1 | 30 days | Account connected. Minimal or no activity, low follower count. |
| **Farcaster** | Medium | 1 | 60 days | Account with moderate casting history, some followers, and reasonable account age. |
| **Farcaster** | High | 1 | 90 days | Established account with consistent activity, meaningful follower base, and significant account age. |
| **GitHub** | Low | 2 | 30 days | Account connected. Few or no public repos, minimal contribution history. |
| **GitHub** | Medium | 2 | 60 days | Account with several repos, some contribution history and commit activity. |
| **GitHub** | High | 2 | 90 days | Established account with extensive contribution graph, multiple repos, and significant account age. |
| **X (Twitter)** | Low | 3 | 30 days | Account connected. Low follower count, minimal post history. |
| **X (Twitter)** | Medium | 3 | 60 days | Account with moderate followers, regular posting activity, and reasonable account age. |
| **X (Twitter)** | High | 3 | 90 days | Established account with a strong follower base, consistent activity, and significant account age. |
| **zkPassport** | — | — | 180 days | Prove passport verification via zero-knowledge proof. Binary credential. |
| **Self** | — | — | 180 days | Prove passport verification via Self protocol. Binary credential. |
| **Uber Rides** | — | — | 180 days | Prove at least 5 completed Uber trips. Binary credential. |
| **Apple Subs** | — | — | 180 days | Prove an active Apple subscription (e.g. iCloud, Apple Music, Apple One). Binary credential. |
| **Binance KYC** | — | — | 180 days | Prove your Binance account has passed KYC verification. Binary credential. |
| **OKX KYC** | — | — | 180 days | Prove your OKX account has passed KYC verification. Binary credential. |

> **Family enforcement:** Groups in the same family (e.g. Farcaster Low/Medium/High) share a registration hash, so a user can only hold one credential per family per app. Group changes within a family go through the recovery timelock. Standalone credentials (family = 0) have no such constraint.

## 2. Default Scorer

| Credential | Group | Score |
|---|---|---|
| Farcaster | Low | 2 |
| Farcaster | Medium | 5 |
| Farcaster | High | 10 |
| GitHub | Low | 2 |
| GitHub | Medium | 5 |
| GitHub | High | 10 |
| X (Twitter) | Low | 2 |
| X (Twitter) | Medium | 5 |
| X (Twitter) | High | 10 |
| zkPassport | — | 20 |
| Self | — | 20 |
| Uber Rides | — | 10 |
| Apple Subs | — | 10 |
| Binance KYC | — | 20 |
| OKX KYC | — | 20 |

> **Scoring rationale:** KYC and passport credentials carry the highest weight (20) as they provide the strongest proof of unique personhood. Social accounts scale from low (2) to high (10) based on the confidence that a real, unique person is behind the account. Real-world activity proofs (Uber, Apple Subs) sit in between at 10, reflecting meaningful but non-identity-level verification.
