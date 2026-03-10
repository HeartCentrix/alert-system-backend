# Database Migration & Schema Management

## Overview

This project uses Alembic for database migrations with automatic schema validation to prevent column mismatch errors in production.

## Security Improvements (March 2026)

### Password Reset Token Hashing

**Problem**: Password reset tokens were stored in plaintext. If the database was compromised, attackers could use stolen tokens to reset user passwords.

**Solution**: Tokens are now hashed with SHA-256 before storage.

- `forgot-password` endpoint: Generates plaintext token → hashes it → stores hash in DB → sends plaintext via email
- `reset-password` endpoint: Hashes incoming token → compares with stored hash
- **Security benefit**: Database leaks don't expose usable reset tokens

### MFA Secret Encryption

**Problem**: MFA secrets were stored in plaintext. Database compromise allowed attackers to generate valid TOTP codes.

**Solution**: MFA secrets are now encrypted at rest using Fernet (AES-CBC + HMAC).

- Secrets encrypted before storing to database
- Automatically decrypted during TOTP verification
- **Security benefit**: Encrypted secrets can't be used directly in authenticator apps
- **Backward compatible**: Existing plaintext secrets continue to work

### Migration Required

Run the following to apply security improvements:

```bash
# Generate new MFA encryption key (store securely in environment)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Add to Railway environment variables:
MFA_ENCRYPTION_KEY="<generated-key>"

# Run migrations
alembic upgrade head
```

The migration `expand_mfa_secret_column` expands the `mfa_secret` column from 32 to 255 characters to accommodate Fernet-encrypted tokens (~140 characters).

### Lazy Migration for Existing Users

Existing users with plaintext MFA secrets are handled automatically:
- `decrypt_mfa_secret()` detects plaintext vs encrypted format
- Plaintext secrets (not starting with `gAAAAA`) are returned as-is
- On next MFA operation, secrets can be re-encrypted

## Deployment Checklist for Security Improvements

### Pre-Deployment

1. **Generate MFA Encryption Key**
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   Save this key securely. It must be the same across all instances.

2. **Add Environment Variable to Railway**
   ```
   MFA_ENCRYPTION_KEY="<your-generated-key>"
   ```
   **WARNING**: If this key is lost or changed:
   - All encrypted MFA secrets become unreadable
   - MFA users cannot log in
   - Admin must reset MFA for all affected users

3. **Backup Database**
   ```bash
   # Create a backup before running migrations
   pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql
   ```

### Deployment

1. **Deploy code changes** (Railway will automatically run migrations)

2. **Verify migrations ran**
   ```bash
   # Check migration status
   alembic current
   
   # Should show: expand_mfa_secret_column (head)
   ```

3. **Verify column size increased**
   ```sql
   -- Check mfa_secret column type
   \d users
   
   -- Should show: mfa_secret character varying(255)
   ```

### Post-Deployment Verification

1. **Test Password Reset Flow**
   ```bash
   # Request password reset
   curl -X POST https://your-backend/api/v1/auth/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com"}'
   
   # Check database - token should be hashed (64-char hex)
   SELECT email, password_reset_token FROM users WHERE email = 'test@example.com';
   ```

2. **Test MFA Enrollment**
   ```bash
   # Enroll in MFA (via login flow)
   # Check database - secret should be encrypted (starts with gAAAAA)
   SELECT email, mfa_secret FROM users WHERE mfa_enabled = true;
   ```

3. **Test MFA Login**
   - Log in with MFA-enabled account
   - Verify TOTP code from authenticator app works

4. **Test Existing MFA Users**
   - Existing users with plaintext secrets should still be able to log in
   - Lazy migration will handle decryption automatically

### Rollback Plan

If issues occur:

1. **Revert code deployment**

2. **Rollback migration** (only if no encrypted secrets exist yet)
   ```bash
   alembic downgrade -1
   ```

3. **Restore from backup** if encrypted secrets were created

## Troubleshooting

### MFA Login Fails After Deployment

**Symptom**: Users with existing MFA cannot log in

**Cause**: MFA_ENCRYPTION_KEY not set or wrong key

**Solution**:
1. Verify `MFA_ENCRYPTION_KEY` is set in Railway environment
2. Check application logs for decryption errors
3. If key was changed, restore the original key or reset MFA for affected users

### Password Reset Token Not Working

**Symptom**: Users report "Invalid or expired reset token"

**Cause**: Token hashing not working correctly

**Solution**:
1. Check logs for hash verification errors
2. Verify `hash_password_reset_token` function is being called
3. Ensure token in email matches what user enters (no whitespace issues)

### Database Migration Fails

**Symptom**: `expand_mfa_secret_column` migration fails

**Cause**: Column already exists with different type

**Solution**:
1. Check current column type: `\d users`
2. If already 255, migration already ran - update migration history
3. If different error, check PostgreSQL logs

## Architecture

### Migration Files
Located in `alembic/versions/`:
- Each migration adds/modifies database schema
- Migrations run automatically on deployment
- Downgrade scripts available for rollback

### Schema Validation Scripts

#### `scripts/check_schema.py`
Pre-deployment validation script. Use in CI/CD:
```bash
python scripts/check_schema.py
# Returns: 0 = valid, 1 = has issues
```

#### `scripts/validate_db_schema.py`
Interactive schema validation and auto-fix:
```bash
# Dry-run (show issues without fixing)
python scripts/validate_db_schema.py

# Auto-fix (add missing columns)
python scripts/validate_db_schema.py --fix
```

### Startup Script

`start.sh` - Runs on every deployment:
1. Validates database schema
2. Auto-fixes missing columns
3. Runs Alembic migrations
4. Starts the application

## Creating New Migrations

### For New Models/Columns

1. **Add the model/column to `app/models.py`**

2. **Generate migration automatically:**
   ```bash
   alembic revision --autogenerate -m "description of change"
   ```

3. **Review the generated migration** in `alembic/versions/`

4. **Test locally:**
   ```bash
   alembic upgrade head
   ```

### For Data Preservation (user_email pattern)

When adding foreign keys to users, always add `user_email` for data preservation:

```python
user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
user_email = Column(String(255), nullable=True)  # Preserved after user deletion
```

Then create a migration:
```bash
alembic revision -m "add user_email to <table_name>"
```

Edit the migration to check if column exists before adding.

## Deployment Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Railway Deploy                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  1. start.sh executes                                       │
│     - python scripts/validate_db_schema.py --fix            │
│     - alembic upgrade head                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Schema Validation                                       │
│     - Checks all model columns exist in DB                  │
│     - Auto-adds missing columns                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Alembic Migrations                                      │
│     - Runs all pending migrations                           │
│     - Updates alembic_version table                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Application Starts                                      │
│     - uvicorn starts on port 8000                           │
└─────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Column Does Not Exist Error

If you see errors like:
```
sqlalchemy.exc.ProgrammingError: column table_name.column_name does not exist
```

**Immediate fix:**
```bash
# On production (Railway)
# The startup script will auto-fix on next deploy

# Locally
python scripts/validate_db_schema.py --fix
```

**Prevent future issues:**
1. Always create migrations for model changes
2. Run `alembic upgrade head` before testing locally
3. Use `scripts/check_schema.py` in CI/CD

### Migration Conflicts

If migrations are out of order:
```bash
# Check current revision
alembic current

# See all migrations
alembic history

# Fix: Update down_revision in migration file
# Then re-run
alembic upgrade head
```

### Rollback Migrations

```bash
# Rollback one migration
alembic downgrade -1

# Rollback to specific revision
alembic downgrade <revision_id>

# Rollback all (careful!)
alembic downgrade base
```

## Best Practices

1. **Always create migrations for schema changes** - Never modify DB manually
2. **Test migrations locally first** - Run `alembic upgrade head` before deploying
3. **Add user_email for audit tables** - Preserves data after user deletion
4. **Use ON DELETE SET NULL** - For foreign keys to users table
5. **Run schema validation in CI/CD** - Catch issues before production
6. **Keep migrations small and focused** - One change per migration
7. **Never edit applied migrations** - Create new ones for changes

## Migration Chain

Current migration order:
```
location_audience_v1
  ↓
add_audit_log_user_email
  ↓
remove_user_deleted_at
  ↓
add_user_email_columns (delivery_logs, notification_responses)
  ↓
fix_audit_logs_fk
  ↓
add_user_email_incoming (incoming_messages)
  ↓
ensure_all_user_email_columns (all tables)
  ↓
ensure_all_columns_exist (comprehensive check)
```

## Environment Variables

```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

Required for migrations to run.
