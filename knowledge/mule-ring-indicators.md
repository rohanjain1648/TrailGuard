# Mule ring indicators

## Shared infrastructure

- One device fingerprint logging into three or more accounts within a day. Households share at most two.
- Emulator fingerprints.
- IP addresses in the same /24 subnet across unrelated accounts.

## Money movement

- A micro-charge under 2 units (card test) shortly after a new-device login.
- Several accounts adding the same payee within hours, often in a foreign country.
- Transfers to a payee added less than a day earlier, many times the customer's usual amount.

## Response

- Block money movement from any account on a device already linked to a blocked case.
- Once a device fingerprint or mule payee is confirmed in an attacker pattern, block on first sight (step-up policy §3).
