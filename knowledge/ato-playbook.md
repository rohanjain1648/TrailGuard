# Account takeover playbook

How account takeover (ATO) unfolds, and the earliest point at which each kind can be stopped. Each step alone usually looks harmless to the one team that sees it, so the playbook depends on the login, device, recovery and payments agents sharing what they see.

## Credential stuffing

Attackers replay leaked passwords across many accounts through rotating residential proxies, so no single IP looks noisy. The few accounts that succeed are logged into from a new device, a new payee is added, and the balance is transferred out. Earliest stop: the new-device login, when it follows failed logins and the payee add. Completion: the transfer.

## SIM swap through support

The attacker contacts support claiming a lost phone and asks to move the number. With the number moved, they reset the password by SMS, log in from a new device and drain the account. Earliest stop: the phone change, if support contact came from an unfamiliar network. Completion: the password reset. Never trust an SMS step-up after a phone change (step-up policy §2).

## Session hijack

A phished session is used from another country shortly after the genuine customer's login, then the email and password are changed to lock the owner out. Earliest stop: the impossible-travel login. Completion: the password reset.

## Mule ring

One emulator or device farm works through several accounts in turn: log in, test a card with a micro-charge, add the same mule payee, transfer. Earliest stop: the third account seen on the same device, or the first account once that device or mule payee is a known indicator. Completion: each transfer.

## Low and slow

A patient attacker spreads the takeover over days: an abandoned password reset, a few failed logins, an MFA device added by email link, a new-device login, a card test, then the transfer. Each step stays under any single team's threshold. Earliest stop: the MFA device change once earlier steps are visible together. Completion: the transfer.

## Benign look-alikes

Customers travel with their own phones, upgrade devices, forget passwords, share a family tablet, pay a new landlord and genuinely lose phones. A single signal is never enough to block. Prefer step-up over block unless several agents agree.
