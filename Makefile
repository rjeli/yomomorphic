gates.json:
	yosys -s synthesize.ys

.PHONY: clean
clean:
	rm *.ilang gates.json
