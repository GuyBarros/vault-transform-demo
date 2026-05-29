vault {
  address = "http://127.0.0.1:8200"
}

# Authenticate once, write the token to a sink file, then exit.
# The run_demo.sh wrapper reads the token and passes it to demo_all.py as
# VAULT_TOKEN so the demo never needs AppRole credentials at runtime.
exit_after_auth = true

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = ".vault/role_id"
      secret_id_file_path = ".vault/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = ".vault/token"
      mode = 0600
    }
  }
}
