module top(
    input clk,
    output reg [7:0] cnt,
);
    always @(posedge clk) begin
        cnt <= cnt + 1;
    end
endmodule
