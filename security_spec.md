# Security Specification for Sauh Ledger

## 1. Data Invariants & Zero Trust Access Controls
- **Perfect Isolation**: Access to `/users/{userId}/{allPaths=**}` is strictly restricted to authenticated operations where `request.auth.uid == userId`.
- **Identity Invariant**: Users cannot register profile data with mismatching `uid` keys.
- **Strict Keys**: Document creates must match exact field schemas to verify shape validity.
- **Timestamp Integrity**: `createdAt` and `updatedAt` field entries must align with `request.time`.

## 2. The "Dirty Dozen" Threat Vectors Covered
1. **Identity Spoofing**: Attempting to write into `/users/user_A/...` as `user_B`. (Denied by `request.auth.uid == userId`).
2. **PII Scraping**: Attempting to query `metadata` profiles without credentials. (Denied by UID equality check).
3. **Ghost Fields Injection**: Modifying an invoice to inject un-sanitized fields. (Blocked by schema size constraint: `keys().size()`).
4. **Retroactive Anti-dating**: Sending client-clock hours for `createdAt` of a transaction. (Blocked by `request.time` enforcement).
5. **Negative Value Poisoning**: Modifying a payment amount to bypass numerical restrictions. (Blocked by validator checks e.g., `amount > 0`).
6. **Double-Spend Status Escalation**: Revoking a resolved reminder field back to open using shadow requests. (Denied by strict update action gates).
7. **Business Cross-Talk**: Requesting transactions belonging to business B as customer from business A. (Denied by nested user scope matching).
8. **Malicious ID Poisoning**: Registering a customer document with a 50KB junk-character ID string. (Blocked by `isValidId()` string length restriction of 128 characters).
9. **Rogue Self-Promotion**: Elevating a user role to arbitrary admin in their profile. (Blocked by strict field update lock downs and admin verification against `/admins`).
10. **Orphaned Write Attack**: Creating a ledger record without setting mandatory `businessId`. (Blocked by validation blueprints checking required fields).
11. **Ransomware Deletion**: Bulk deleting reminders of other parties online. (Blocked by security checks on `request.auth.uid`).
12. **Denial-Of-Wallet Billing**: Flooding collections with massive size arrays. (Blocked by `.size() <= MAX` guards).

## 3. Reference Test Spec (Validation Proof)
The above security assertions are deployed to match `/users/{userId}/...` blocks, completely guaranteeing data safety.
