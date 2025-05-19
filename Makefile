clean_postgres:
	docker compose down
	docker volume rm grs_postgres_data