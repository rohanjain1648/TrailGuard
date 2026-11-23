# Step-up policy

Decision policy for escalated account-takeover cases. The Sentinel applies it to every case its channel agents escalate (a case is escalated when its risk score reaches 40).

## §1 Risk thresholds

- Risk 80 or more: **BLOCK** money movement (payee add, card test, transfer) and new-device sessions. **HOLD** credential changes (phone, email, password reset, MFA device) for an analyst.
- Risk 50 to 79: **STEP_UP**. Ask for extra verification through the customer's registered second factor before the action proceeds.
- Risk below 50: **ALLOW**, and keep watching.

## §2 Second factor recently changed

If the phone number or an MFA device on the account changed in the last 72 hours, a step-up challenge would be delivered to whoever made that change, possibly the attacker. In that case **HOLD** instead of STEP_UP, at any risk from 50 upward.

## §3 Known attacker indicator

If any device fingerprint, IP subnet or payee in the case appears in a confirmed attacker pattern, **BLOCK** the action whatever the risk score, and link the case to that pattern.

## §4 Explaining a decision

Every decision must name the evidence it relied on (which agent saw what, and when), the section of this policy applied, and any confirmed pattern matched. The explanation must be readable by a customer-support colleague with no engineering background.
