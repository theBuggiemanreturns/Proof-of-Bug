module zero_mint(input [7:0] amt, input [7:0] shares, output bug);
  assign bug = (amt != 0) & (shares == 0);
endmodule
module full_adder(input a, input b, input cin, output sum, output cout);
  assign {cout, sum} = a + b + cin;
endmodule
