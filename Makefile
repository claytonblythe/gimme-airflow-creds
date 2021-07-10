init:
	pip3 install -r requirements_dev.txt

docker-build:
	docker build -t gimme-airflow-creds .

test: docker-build
	nosetests -vv tests
