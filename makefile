all: clean run

run:
	python beebox_ssrf.py -c config.yml

clean: 
	rm -drf output