.PHONY: test-setup test

test-setup:
	docker pull n3llyb0y/wait
	docker pull progrium/consul

test:
	cd assets/service_discovery; docker-compose build --no-cache 2>&1 >/dev/null
	nosetests suite
