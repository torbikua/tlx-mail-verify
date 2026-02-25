.PHONY: help build up down logs restart clean

help:
	@echo "Mail Address Verifier - Commands:"
	@echo "  make build    - Build Docker images"
	@echo "  make up       - Start services"
	@echo "  make down     - Stop services"
	@echo "  make logs     - View logs"
	@echo "  make restart  - Restart services"
	@echo "  make clean    - Clean up containers and volumes"
	@echo "  make shell    - Open shell in app container"

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Services started!"
	@echo "Web interface: http://localhost:8080"

down:
	docker-compose down

logs:
	docker-compose logs -f app

restart:
	docker-compose restart

clean:
	docker-compose down -v
	rm -rf logs/*.log
	rm -rf data/attachments/*
	rm -rf data/reports/*

shell:
	docker-compose exec app /bin/bash
