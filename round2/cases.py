"""Round 2 cases: contracts from the independent author session (round2/src, byte-for-byte from its
messages; hashes in round2/RECEIVED.sha256) and deployments translated literally from each file's
DEPLOY note.

Translation policy: blind/cases.py's policy, unchanged, plus the address mapping these notes need:
  - the "deployer" is the test runner (address(this)): it deploys, owns, mints and makes admin calls
  - the note's user addresses map in order: 0x1111... -> U0, 0x2222... -> U1, 0x3333... -> U2
  - amounts given in a note are used exactly; "approves X" with no amount = approves the maximum
  - a note that says a user "may be a contract with a receive/fallback function" (or where the
    contract sends ETH/calls to msg.sender): U1 is a contract that may call back (attacker=1)
  - "any other address may also call": one extra model user beyond those named
  - the first contract named "under test" is A0; helpers follow; `order` is the note's deploy order
No rules here: rules come only from round2/proposals/<id>.json (the rule writer, after review).
"""
S = "round2/src/"
USERS = ["{U0}", "{U1}", "{U2}", "{U3}"]
MAX = "type(uint256).max"


def for_users(stmt, users=USERS):
    return [stmt.replace("{U}", u) for u in users]


def tok(i, name, dec, alias=None, f=None):
    d = dict(name="MockToken", file=f, args=f'abi.encode("{name}", uint8({dec}))')
    if alias:
        d["alias"] = alias
    return d


def dual_vault(cid):
    f = S + f"{cid}.sol"
    return dict(id=cid, title=f"round2 {cid}",
                contracts=[dict(name="DualAssetVault", file=f, args="abi.encode({A1}, {A2})"),
                           tok(1, "Stable A", 18, "MockToken_A", f), tok(2, "Stable B", 18, "MockToken_B", f)],
                order=[1, 2, 0],
                setup=["MockToken({A1}).mint({U0}, 100e18);", "MockToken({A2}).mint({U0}, 100e18);",
                       "vm.prank({U0}); MockToken({A1}).approve({A0}, " + MAX + ");",
                       "vm.prank({U0}); MockToken({A2}).approve({A0}, " + MAX + ");",
                       "{{ uint256[] memory amts = new uint256[](2); amts[0] = 100e18; amts[1] = 100e18;"
                       " vm.prank({U0}); DualAssetVault({A0}).depositMulti(amts); }}",
                       "MockToken({A1}).mint({U1}, 100e18);", "MockToken({A2}).mint({U1}, 100e18);",
                       "vm.prank({U1}); MockToken({A1}).approve({A0}, " + MAX + ");",
                       "vm.prank({U1}); MockToken({A2}).approve({A0}, " + MAX + ");"])


def reward_pool(cid):
    f = S + f"{cid}.sol"
    return dict(id=cid, title=f"round2 {cid}",
                contracts=[dict(name="RewardPool", file=f, args="abi.encode({A1}, {A2}, {A3})"),
                           tok(1, "Stake Token", 18, "MockToken_STK", f), tok(2, "Reward Token", 18, "MockToken_RWD", f),
                           dict(name="LegacyPool", file=f, args="abi.encode({A1})")],
                order=[1, 2, 3, 0],
                setup=["LegacyPool({A3}).setMigrator({A0});",
                       "MockToken({A1}).mint({U0}, 100e18);",
                       "vm.prank({U0}); MockToken({A1}).approve({A0}, " + MAX + ");",
                       "vm.prank({U0}); RewardPool({A0}).stake(100e18);",
                       "MockToken({A2}).mint(address(this), 1_000e18);",
                       "MockToken({A2}).approve({A0}, " + MAX + ");",
                       "RewardPool({A0}).notifyReward(1_000e18);",
                       "MockToken({A1}).mint({U1}, 100e18);",
                       "vm.prank({U1}); MockToken({A1}).approve({A3}, " + MAX + ");",
                       "vm.prank({U1}); MockToken({A1}).approve({A0}, " + MAX + ");"])


CASES = [
    dict(id="R01", title="round2 R01",
         contracts=[dict(name="VestingPool", file=S + "R01.sol", args="abi.encode({A1})"),
                    tok(1, "Project Token", 18, f=S + "R01.sol")],
         order=[1, 0],
         setup=["MockToken({A1}).mint({U0}, 100e18);", "vm.prank({U0}); MockToken({A1}).approve({A0}, 100e18);",
                "MockToken({A1}).mint({U1}, 100e18);", "vm.prank({U1}); MockToken({A1}).approve({A0}, 100e18);",
                "vm.prank({U0}); VestingPool({A0}).createLock({U0}, 100e18, 100);"]),

    dict(id="R02", title="round2 R02", attacker=1,
         contracts=[dict(name="TimeLockedSavings", file=S + "R02.sol", args="''")],
         setup=["vm.deal({U0}, 5 ether);", "vm.prank({U0}); TimeLockedSavings({A0}).deposit{{value: 5 ether}}(7 days);",
                "vm.deal({U1}, 5 ether);"]),

    dict(id="R03", title="round2 R03",
         contracts=[dict(name="LiquidityVault", file=S + "R03.sol", args="abi.encode({A1})"),
                    tok(1, "USD Stable", 18, f=S + "R03.sol")],
         order=[1, 0],
         setup=["MockToken({A1}).mint(address(this), 500e18);", "MockToken({A1}).approve({A0}, " + MAX + ");",
                "LiquidityVault({A0}).addIncentives(500e18);",
                "MockToken({A1}).mint({U0}, 1_000e18);", "vm.prank({U0}); MockToken({A1}).approve({A0}, " + MAX + ");",
                "MockToken({A1}).mint({U1}, 1_000e18);", "vm.prank({U1}); MockToken({A1}).approve({A0}, " + MAX + ");"]),

    dict(id="R04", title="round2 R04", users=3,  # "any other address may also call": U2
         contracts=[dict(name="StakeLedger", file=S + "R04.sol", args="''")],
         setup=["StakeLedger({A0}).credit({U0}, 100e18);", "StakeLedger({A0}).grantVesting({U1}, 20e18);"]),

    dict(id="R05", title="round2 R05",
         contracts=[dict(name="BridgeGateway", file=S + "R05.sol", args="abi.encode({A1}, int256(1e6))"),
                    tok(1, "Wrapped Asset", 8, f=S + "R05.sol")],
         order=[1, 0],
         setup=["MockToken({A1}).mint({U0}, 1_000e8);", "vm.prank({U0}); MockToken({A1}).approve({A0}, " + MAX + ");",
                "vm.prank({U0}); BridgeGateway({A0}).lockIn(1_000e8);",
                "MockToken({A1}).mint({U1}, 10e8);", "vm.prank({U1}); MockToken({A1}).approve({A0}, " + MAX + ");"]),

    dict(id="R06", title="round2 R06", users=3,
         contracts=[dict(name="ManagedTreasury", file=S + "R06.sol", args="abi.encode({A1})"),
                    tok(1, "Wrapped BTC", 8, f=S + "R06.sol")],
         order=[1, 0],
         setup=["ManagedTreasury({A0}).setRebalancer({U2});", "ManagedTreasury({A0}).setRebalancer({U1});",
                "MockToken({A1}).mint({U0}, 10e8);", "vm.prank({U0}); MockToken({A1}).approve({A0}, " + MAX + ");",
                "vm.prank({U0}); ManagedTreasury({A0}).deposit(10e8);"]),

    dual_vault("R07"),
    reward_pool("R08"),

    dict(id="R09", title="round2 R09",
         contracts=[dict(name="DeflationaryToken", file=S + "R09.sol", args="abi.encode(10_000e18)"),
                    tok(1, "USD Stable", 18, f=S + "R09.sol"),
                    dict(name="SimplePair", file=S + "R09.sol", args="abi.encode({A0}, {A1})")],
         order=[0, 1, 2],
         setup=["DeflationaryToken({A0}).setPair({A2});",
                "MockToken({A1}).mint(address(this), 1_000e18);",
                "DeflationaryToken({A0}).transfer({A2}, 1_000e18);", "MockToken({A1}).transfer({A2}, 1_000e18);",
                "SimplePair({A2}).sync();",
                "DeflationaryToken({A0}).transfer({U1}, 2_000e18);",
                "MockToken({A1}).mint({U0}, 1_000e18);"]),

    dual_vault("R10"),

    dict(id="R11", title="round2 R11",
         contracts=[dict(name="StablePool", file=S + "R11.sol", args="abi.encode({A1})"),
                    tok(1, "USD Coin", 6, f=S + "R11.sol")],
         order=[1, 0],
         setup=["MockToken({A1}).mint({U0}, 1_000e6);", "vm.prank({U0}); MockToken({A1}).approve({A0}, " + MAX + ");",
                "vm.prank({U0}); StablePool({A0}).deposit(1_000e18);",
                "MockToken({A1}).mint({U1}, 10e6);", "vm.prank({U1}); MockToken({A1}).approve({A0}, " + MAX + ");"]),

    reward_pool("R12"),
]

for c in CASES:
    c.setdefault("rules", {})
