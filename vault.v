// Circuit model of Vault.sol: 8-bit numbers, a 3-transaction sequence chosen by the solver.
// Each step: op (0 = deposit, 1 = donate) + amount. Start state is an empty vault.
// Output bug = 1  <=>  some deposit of >0 assets minted 0 shares (depositor loses funds).
// Output valid = 0 if any number overflowed 8 bits (shrinking artefact, not a real bug).
module vault #(parameter PATCHED = 0) (
    input  op0, op1, op2,
    input  [7:0] amt0, amt1, amt2,
    output bug, valid
);
    wire [7:0] a0 = 0, s0 = 0;
    wire [7:0] a1, s1, a2, s2, a3, s3;
    wire b0, b1, b2, v0, v1, v2;
    step #(PATCHED) t0(op0, amt0, a0, s0, a1, s1, b0, v0);
    step #(PATCHED) t1(op1, amt1, a1, s1, a2, s2, b1, v1);
    step #(PATCHED) t2(op2, amt2, a2, s2, a3, s3, b2, v2);
    assign valid = v0 & v1 & v2;
    assign bug   = valid & (b0 | b1 | b2);
endmodule

module step #(parameter PATCHED = 0) (
    input op, input [7:0] amt, input [7:0] ta, input [7:0] ts,
    output [7:0] ta_n, output [7:0] ts_n, output zero_mint, output ok
);
    // shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets
    wire [15:0] prod   = amt * ts;
    wire [15:0] q;
    divu16x8 d(prod, ta, q);
    wire [7:0]  shares = (ts == 0) ? amt : q[7:0];
    wire is_dep  = (op == 1'b0);
    wire reverts = PATCHED && is_dep && (shares == 0);
    wire [8:0] na = ta + amt;              // both ops add assets
    wire [8:0] ns = ts + (is_dep ? shares : 8'd0);
    assign ta_n = reverts ? ta : na[7:0];
    assign ts_n = reverts ? ts : ns[7:0];
    assign zero_mint = is_dep & !reverts & (amt != 0) & (shares == 0);
    // no overflow, quotient fits, and no division by zero when supply>0
    assign ok = reverts | (!na[8] & !ns[8] & (q[15:8] == 0) & !(ts != 0 && ta == 0 && is_dep));
endmodule

// Restoring long division, 16-bit / 8-bit (the textbook shift-and-subtract method).
// Divide by zero gives 0 here; that case is flagged as not-ok by the caller anyway.
module divu16x8(input [15:0] n, input [7:0] d, output [15:0] q);
    wire [8:0] r [0:16];
    assign r[0] = 9'd0;
    genvar i;
    generate for (i = 0; i < 16; i = i + 1) begin : g
        wire [9:0] sh   = {r[i], n[15-i]};
        wire [9:0] diff = sh - {2'b0, d};
        wire take = !diff[9] && (d != 0);
        assign q[15-i] = take;
        assign r[i+1]  = take ? diff[8:0] : sh[8:0];
    end endgenerate
endmodule
