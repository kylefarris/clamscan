.PHONY: all
TESTS = tests/*.js

all:
	@npm install

test: all
	@mkdir -p tests/infected
	@mkdir -p tests/bad_scan_dir
	@touch tests/clamscan-log
	@./node_modules/.bin/mocha --timeout 5000 --check-leaks --reporter spec $(TESTS)

clean:
	rm -rf node_modules
