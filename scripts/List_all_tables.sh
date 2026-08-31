# List all tables
docker exec -it postgres-transform-demo psql -U vault_demo -d vault_demo -c "\dt"

# Read all customers
docker exec -it postgres-transform-demo psql -U vault_demo -d vault_demo -c "SELECT * FROM clientes_staging;"

# Count rows
docker exec -it postgres-transform-demo psql -U vault_demo -d vault_demo -c "SELECT COUNT(*) FROM customers;"

# Read specific columns (PII fields)
docker exec -it postgres-transform-demo psql -U vault_demo -d vault_demo -c "SELECT nome, cpf_protected, email_masked, pan_protected FROM customers LIMIT 10;"
