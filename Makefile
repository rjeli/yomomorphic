gates.json: synthesize.ys hardware.v cell_library.liberty
	yosys -s synthesize.ys

.PHONY: clean
clean:
	rm -f *.ilang gates.json *.dot *.png
