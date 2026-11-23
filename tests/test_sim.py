from collections import Counter

from trailguard.sim import attack_instances, generate

TTPS = {"credential_stuffing", "sim_swap", "session_hijack", "mule_ring", "low_and_slow"}
BAITS = {"traveller", "phone_upgrade", "forgetful", "family_device", "big_purchase", "new_landlord", "lost_phone"}


def test_deterministic():
    a = [e.to_dict() for e in generate(7, n_events=600)]
    b = [e.to_dict() for e in generate(7, n_events=600)]
    assert a == b


def test_sorted_and_unique_ids():
    ev = generate(3, n_events=600)
    assert [e.ts for e in ev] == sorted(e.ts for e in ev)
    assert len({e.event_id for e in ev}) == len(ev)


def test_each_attack_has_one_completion():
    inst = attack_instances(generate(1, n_events=600))
    assert inst
    for steps in inst.values():
        assert sum(e.truth.completes_takeover for e in steps) == 1


def test_all_ttps_present():
    inst = attack_instances(generate(2, n_events=600))
    assert {steps[0].truth.ttp for steps in inst.values()} == TTPS


def test_benign_bait_present():
    ev = generate(4, n_events=600)
    assert {e.truth.benign_case for e in ev if e.truth.benign_case} == BAITS


def test_device_seen_precedes_login():
    ev = generate(5, n_events=600)
    seen = {(e.account_id, e.ts) for e in ev if e.type == "device_seen"}
    for e in ev:
        if e.type == "login_success":
            from datetime import timedelta

            assert (e.account_id, e.ts - timedelta(seconds=1)) in seen


def test_epoch2_reuses_infra():
    e1 = generate(9, epoch=1, n_events=600)
    e2 = generate(9, epoch=2, n_events=600)

    def mules(ev):
        return {e.attrs["payee_id"] for e in ev if e.type == "payee_add" and e.is_attack}

    assert mules(e1) & mules(e2)
    victims1 = {e.account_id for e in e1 if e.is_attack}
    victims2 = {e.account_id for e in e2 if e.is_attack}
    assert not victims1 & victims2


def test_size():
    assert 1700 <= len(generate(1, n_events=2000)) <= 2300


def test_channels_valid():
    c = Counter(e.channel for e in generate(6, n_events=600))
    assert set(c) == {"login", "device", "recovery", "payments"}
