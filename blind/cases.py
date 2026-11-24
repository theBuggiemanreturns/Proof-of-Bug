"""Blind cases: contracts from the independent author (blind/src, byte-for-byte from its
messages) and deployments translated literally from each file's DEPLOY note.

Translation policy (fixed before writing any case, applied to all):
  - the "deployer" is the test runner (address(this)): it deploys, owns, mints and calls admin setup
  - amounts given in a DEPLOY note are used exactly; amounts not given are 100 base units per user
  - "users" are the model's users U0, U1, ... (addresses 0x31...); setup mints to U0..U3 and they
    approve the maximum (as real users do); everything else the note leaves to users is left to the
    solver (deposits, borrows, ...)
  - when a note says the owner keeps acting as part of normal operation ("periodically"), the
    deployer/owner is a model user (U2) so the solver can also play the owner [added for C06,
    the first note that says so]
  - addresses the deployment itself uses (e.g. a dead address that receives minted shares) are
    added to the model's address universe [added for C08]
  - when the contract under test calls an address a user controls (sends ETH to msg.sender...),
    user U1 is a contract that may call back once per transaction (attacker=1), as in M02
    [mechanical: applies to C03 and C12]
  - the main contract under test is at A0 (0x99); the others follow at A1, A2, ...; `order`
    gives the deployment order when a constructor needs another contract to exist
No rules here: rules come only from blind/proposals/<id>.json (the rule writer).
"""

S = "blind/src/"
USERS = ["{U0}", "{U1}", "{U2}", "{U3}"]
MAX = "type(uint256).max"


def for_users(stmt):
    return [stmt.replace("{U}", u) for u in USERS]


CASES = [
    dict(id="C01", title="blind C01",
         contracts=[dict(name="VaultC01", file=S + "C01.sol", args="abi.encode({A1})"),
                    dict(name="TokenC01", file=S + "C01.sol", args='abi.encode("Wrapped Dollar", "WD")')],
         order=[1, 0],
         setup=for_users("TokenC01({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC01({A1}).approve({A0}, " + MAX + ");")),

    dict(id="C02", title="blind C02",
         contracts=[dict(name="StakingRewardsC02", file=S + "C02.sol", args="abi.encode({A1}, {A2}, 7 days)"),
                    dict(name="TokenC02", alias="TokenC02_STK", file=S + "C02.sol", args='abi.encode("Stake Token", "STK")'),
                    dict(name="TokenC02", alias="TokenC02_RWD", file=S + "C02.sol", args='abi.encode("Reward Token", "RWD")')],
         order=[1, 2, 0],
         # the note gives no reward amount: 100 base units per second of the 7-day period
         setup=["TokenC02({A2}).mint({A0}, 100 * 7 days);",
                "StakingRewardsC02({A0}).notifyRewardAmount(100 * 7 days);"]
               + for_users("TokenC02({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC02({A1}).approve({A0}, " + MAX + ");")),

    dict(id="C03", title="blind C03", attacker=1,
         contracts=[dict(name="EthPoolC03", file=S + "C03.sol", args="''")]),

    dict(id="C04", title="blind C04",
         contracts=[dict(name="LendingC04", file=S + "C04.sol", args="abi.encode({A1}, {A2}, {A3})"),
                    dict(name="TokenC04", alias="TokenC04_USDS", file=S + "C04.sol", args='abi.encode("USD Stable", "USDS")'),
                    dict(name="TokenC04", alias="TokenC04_GCOL", file=S + "C04.sol", args='abi.encode("Gov Collateral", "GCOL")'),
                    dict(name="AmmC04", file=S + "C04.sol", args="abi.encode({A1}, {A2})")],
         order=[1, 2, 3, 0],
         setup=["TokenC04({A1}).mint(address(this), 1_000e18);",
                "TokenC04({A2}).mint(address(this), 1_000e18);",
                "TokenC04({A1}).approve({A3}, " + MAX + ");",
                "TokenC04({A2}).approve({A3}, " + MAX + ");",
                "AmmC04({A3}).addLiquidity(1_000e18, 1_000e18);",
                # the lender: U0 (so the solver can also act as the lender)
                "TokenC04({A1}).mint({U0}, 10_000e18);",
                "vm.prank({U0}); TokenC04({A1}).approve({A0}, " + MAX + ");",
                "vm.prank({U0}); LendingC04({A0}).supply(10_000e18);"]
               # borrowers (and anyone repaying or liquidating) get collateral and stable to work with
               + for_users("TokenC04({A2}).mint({U}, 100);") + for_users("TokenC04({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC04({A2}).approve({A0}, " + MAX + ");")
               + for_users("vm.prank({U}); TokenC04({A1}).approve({A0}, " + MAX + ");")
               + for_users("vm.prank({U}); TokenC04({A1}).approve({A3}, " + MAX + ");")
               + for_users("vm.prank({U}); TokenC04({A2}).approve({A3}, " + MAX + ");")),
]

CASES += [
    dict(id="C05", title="blind C05",
         contracts=[dict(name="VoucherClaimC05", file=S + "C05.sol", args="abi.encode({A1}, address(0x5151))"),
                    dict(name="TokenC05", file=S + "C05.sol", args='abi.encode("Incentive Token", "INC")')],
         order=[1, 0],  # the signer is an off-chain key: address(0x5151), not a model user
         setup=["TokenC05({A1}).mint({A0}, 1_000_000e18);"]),

    dict(id="C06", title="blind C06", users=3, deployer="{U2}",
         contracts=[dict(name="StakedShareC06", file=S + "C06.sol", args="abi.encode({A1}, {A2})"),
                    dict(name="TokenC06", alias="TokenC06_BASE", file=S + "C06.sol", args='abi.encode("Base Asset", "BASE")'),
                    dict(name="TokenC06", alias="TokenC06_BNS", file=S + "C06.sol", args='abi.encode("Bonus", "BNS")')],
         order=[1, 2, 0],
         setup=for_users("vm.prank({U2}); TokenC06({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC06({A1}).approve({A0}, " + MAX + ");")
               # the owner's own periodic step (mint BNS to itself, approve, distribute) is left to the
               # solver playing U2; its approval is given here as the note describes
               + ["vm.prank({U2}); TokenC06({A2}).approve({A0}, " + MAX + ");"]),

    dict(id="C07", title="blind C07",
         contracts=[dict(name="OrderBookC07", file=S + "C07.sol", args="abi.encode({A1}, {A2})"),
                    dict(name="TokenC07", alias="TokenC07_BASE", file=S + "C07.sol", args='abi.encode("Base", "BASE")'),
                    dict(name="TokenC07", alias="TokenC07_QUOTE", file=S + "C07.sol", args='abi.encode("Quote", "QUOTE")')],
         order=[1, 2, 0],
         # every user can be maker or taker: each gets both tokens and approves the book
         setup=for_users("TokenC07({A1}).mint({U}, 100);") + for_users("TokenC07({A2}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC07({A1}).approve({A0}, " + MAX + ");")
               + for_users("vm.prank({U}); TokenC07({A2}).approve({A0}, " + MAX + ");")),

    dict(id="C08", title="blind C08", extra_keys=[0xdead],
         contracts=[dict(name="PairC08", file=S + "C08.sol", args="abi.encode({A1}, {A2})"),
                    dict(name="TokenC08", alias="TokenC08_TKA", file=S + "C08.sol", args='abi.encode("Token A", "TKA")'),
                    dict(name="TokenC08", alias="TokenC08_TKB", file=S + "C08.sol", args='abi.encode("Token B", "TKB")')],
         order=[1, 2, 0],
         # the liquidity provider is U0
         setup=["TokenC08({A1}).mint({U0}, 1_000e18);", "TokenC08({A2}).mint({U0}, 1_000e18);",
                "vm.prank({U0}); TokenC08({A1}).transfer({A0}, 1_000e18);",
                "vm.prank({U0}); TokenC08({A2}).transfer({A0}, 1_000e18);",
                "vm.prank({U0}); PairC08({A0}).mint({U0});"]
               + for_users("TokenC08({A1}).mint({U}, 100);") + for_users("TokenC08({A2}).mint({U}, 100);")),
]

CASES += [
    dict(id="C09", title="blind C09", extra_keys=[0xFEE0],
         contracts=[dict(name="VaultC09", file=S + "C09.sol", args="abi.encode({A1}, address(0xFEE0))"),
                    dict(name="TokenC09", file=S + "C09.sol", args='abi.encode("Wrapped Dollar", "WD")')],
         order=[1, 0],  # the fee recipient is not a user: address(0xFEE0), in the address universe
         setup=for_users("TokenC09({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC09({A1}).approve({A0}, " + MAX + ");")),

    dict(id="C10", title="blind C10",
         contracts=[dict(name="FarmC10", file=S + "C10.sol", args="abi.encode({A1}, {A2}, 1e18)"),
                    dict(name="TokenC10", alias="TokenC10_LP", file=S + "C10.sol", args='abi.encode("LP Token", "LP")'),
                    dict(name="TokenC10", alias="TokenC10_FRM", file=S + "C10.sol", args='abi.encode("Farm Reward", "FRM")')],
         order=[1, 2, 0],
         setup=["TokenC10({A2}).mint({A0}, 1_000_000e18);"]
               + for_users("TokenC10({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC10({A1}).approve({A0}, " + MAX + ");")),

    dict(id="C11", title="blind C11",
         contracts=[dict(name="StreamPayC11", file=S + "C11.sol", args="abi.encode({A1})"),
                    dict(name="TokenC11", file=S + "C11.sol", args='abi.encode("Payroll Dollar", "PUSD")')],
         order=[1, 0],  # any user can be a payer or a recipient
         setup=for_users("TokenC11({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC11({A1}).approve({A0}, " + MAX + ");")),

    dict(id="C12", title="blind C12", attacker=1,
         contracts=[dict(name="AuctionHouseC12", file=S + "C12.sol", args="abi.encode({A1})"),
                    dict(name="TokenC12", file=S + "C12.sol", args='abi.encode("Lot Token", "LOT")')],
         order=[1, 0],  # any user can sell or bid; users hold ETH for bids (the model's default)
         setup=for_users("TokenC12({A1}).mint({U}, 100);")
               + for_users("vm.prank({U}); TokenC12({A1}).approve({A0}, " + MAX + ");")),
]

for c in CASES:
    c.setdefault("rules", {})
