# Risk rules

Risk points each channel agent assigns to a signal. A case's risk is the sum over distinct signals from the last 72 hours, halved for signals older than 24 hours, capped at 100.

## Login agent

| Signal | Points | Meaning |
|---|---|---|
| failed_logins | 10 | 2 or more failed logins on the account within 60 minutes |
| ip_spray | 25 | one IP failed on 5 or more accounts within 60 minutes |
| spray_ip_login | 35 | a successful login from an IP seen spraying passwords |
| new_device_login | 20 (10 on the customer's home network) | first successful login from this device |
| geo_anomaly | 15 (5 on a known device) | login from outside the home country |
| impossible_travel | 35 | country changed within 2 hours of the last login |
| step_up_failed | 50 | the step-up challenge was failed |

## Device agent

| Signal | Points | Meaning |
|---|---|---|
| new_device | 10 | device not seen on this account before |
| emulator | 20 | fingerprint looks like an emulator |
| device_multi_account | 40 | the same device used on 3 or more accounts within 24 hours |

## Recovery and support agent

| Signal | Points | Meaning |
|---|---|---|
| risky_support_contact | 15 (5 from a known IP) | support asked to move the phone number, change email or disable MFA |
| phone_change | 20 | phone number changed |
| email_change | 25 (10 on a known device) | account email changed |
| reset_unknown_device | 15 | password reset requested or completed from an unrecognised device |
| mfa_change | 25 (10 on a known device) | new MFA device added |

## Payments agent

| Signal | Points | Meaning |
|---|---|---|
| new_payee | 10 | a payee was added |
| card_test | 20 | a micro-charge under 2 units, typical of card testing |
| large_transfer | 25 | transfer more than 5 times the customer's typical amount |
| fresh_payee_transfer | 20 | transfer to a payee added in the last 24 hours |

## Shared and learned signals

| Signal | Points | Meaning |
|---|---|---|
| under_watch | 15 | the Sentinel stepped this account up recently |
| case_blocked | 15 | the Sentinel held or blocked this account recently |
| linked_case | 30 | this device, IP or payee was part of another account's blocked or failed case |
| ttp_match | 30 | the case's signal sequence matches the start of a confirmed attacker pattern |
| known_attacker_ioc | 60 | a device, IP subnet or payee is an indicator in a confirmed attacker pattern |

Device signals (new_device, emulator, device_multi_account, new_device_login) count only for the device involved in the action being decided, not for other devices on the same account.

Signals from other accounts count only when they describe shared infrastructure (ip_spray, device_multi_account) or a blocked or failed case that shares this device, IP or payee.
