all: clean run

run:
	python3.10 beebox_ssrf.py -c config.yml

clean: 
	rm -drf output