"""
init_db.py - Database Initialization
======================================

This module initializes the SQLite database by executing the schema.
Provides functions to create, reset, and check database status.
"""

import sqlite3
import os
import sys
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Get the directory containing this file
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

# Add project root to path for imports
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import DATABASE_PATH, DATABASE_TIMEOUT


def get_schema_path() -> str:
    """Get the path to the schema.sql file."""
    return os.path.join(CURRENT_DIR, 'schema.sql')


def get_database_path() -> str:
    """
    Return the configured database path.
    
    Returns:
        str: Absolute path to the database file
    """
    return DATABASE_PATH


def check_database_exists() -> bool:
    """
    Check if the database file exists.
    
    Returns:
        bool: True if database file exists, False otherwise
    """
    return os.path.exists(DATABASE_PATH)


def get_database_info() -> dict:
    """
    Get information about the current database.
    
    Returns:
        dict: Database information including path, size, tables, etc.
    """
    info = {
        'path': DATABASE_PATH,
        'exists': check_database_exists(),
        'size_bytes': 0,
        'size_mb': 0,
        'tables': [],
        'schema_version': None,
        'created_at': None
    }
    
    if info['exists']:
        info['size_bytes'] = os.path.getsize(DATABASE_PATH)
        info['size_mb'] = round(info['size_bytes'] / (1024 * 1024), 2)
        
        try:
            conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
            cursor = conn.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            info['tables'] = [row[0] for row in cursor.fetchall()]
            
            # Get schema version if system_config exists
            if 'system_config' in info['tables']:
                cursor.execute("SELECT value FROM system_config WHERE key = 'schema_version'")
                row = cursor.fetchone()
                if row:
                    info['schema_version'] = row[0]
                    
                cursor.execute("SELECT value FROM system_config WHERE key = 'created_at'")
                row = cursor.fetchone()
                if row:
                    info['created_at'] = row[0]
            
            conn.close()
        except Exception as e:
            logger.warning(f"Could not read database info: {e}")
    
    return info


def initialize_database(force_reset: bool = False) -> bool:
    """
    Initialize the database with the schema.
    Creates tables if they don't exist.
    After schema creation, runs any pending migrations (WAL mode, indexes …).
    
    Args:
        force_reset: If True, delete old database and create fresh one
    
    Returns:
        bool: True if successful, False otherwise
    """
    schema_path = get_schema_path()
    
    # Check if schema file exists
    if not os.path.exists(schema_path):
        logger.error(f"Schema file not found: {schema_path}")
        return False
    
    try:
        # FORCE RESET: Delete old corrupted database
        if force_reset and check_database_exists():
            logger.warning("Forcing database reset - deleting old database")
            os.remove(DATABASE_PATH)
            logger.info(f"Deleted old database: {DATABASE_PATH}")
        
        # Read the schema SQL
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        
        # Ensure database directory exists
        db_dir = os.path.dirname(DATABASE_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
            logger.info(f"Created database directory: {db_dir}")
        
        # Connect to database (creates file if not exists)
        conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
        cursor = conn.cursor()
        
        # Execute the schema
        cursor.executescript(schema_sql)
        
        # alert_rules is now defined in schema.sql — no duplicate DDL here.
        
        # Commit and close
        conn.commit()
        conn.close()
        
        logger.info(f"Database initialized successfully at: {DATABASE_PATH}")
        
        # Run Phase 3 migrations (WAL mode, extra indexes)
        _run_migrations()
        
        return True
        
    except sqlite3.Error as e:
        logger.error(f"SQLite error during initialization: {e}")
        return False
    except IOError as e:
        logger.error(f"IO error reading schema file: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during initialization: {e}")
        return False


def _run_migrations():
    """
    Apply SQL migration scripts from database/migrations/ in sorted order.
    Each migration is executed once; we track applied migrations in system_config.
    """
    migrations_dir = os.path.join(CURRENT_DIR, "migrations")
    if not os.path.isdir(migrations_dir):
        return

    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
        cursor = conn.cursor()

        # Ensure system_config table exists (may not on first run)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Get already-applied migrations
        cursor.execute("SELECT value FROM system_config WHERE key = 'applied_migrations'")
        row = cursor.fetchone()
        applied = set(row[0].split(",")) if row and row[0] else set()

        # Discover .sql AND .py migration files
        migration_files = sorted(
            f for f in os.listdir(migrations_dir)
            if f.endswith(".sql") or f.endswith(".py")
        )
        # Exclude __init__.py and __pycache__ helpers
        migration_files = [
            f for f in migration_files
            if not f.startswith("__")
        ]

        for fname in migration_files:
            if fname in applied:
                continue
            fpath = os.path.join(migrations_dir, fname)
            if fname.endswith(".sql"):
                with open(fpath, "r", encoding="utf-8") as fh:
                    sql = fh.read()
                logger.info(f"Applying SQL migration: {fname}")
                cursor.executescript(sql)
            elif fname.endswith(".py"):
                logger.info(f"Applying Python migration: {fname}")
                try:
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(fname[:-3], fpath)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    # Convention: migration modules expose a run() or migrate() function
                    if hasattr(mod, 'run'):
                        mod.run()
                    elif hasattr(mod, 'migrate'):
                        mod.migrate()
                    elif hasattr(mod, 'run_startup_migrations'):
                        mod.run_startup_migrations()
                    else:
                        logger.debug("Python migration %s has no run/migrate entry point", fname)
                except Exception as py_exc:
                    logger.warning("Python migration %s failed: %s", fname, py_exc)
            applied.add(fname)

        # Persist applied list
        applied_str = ",".join(sorted(applied))
        cursor.execute("""
            INSERT OR REPLACE INTO system_config (key, value, updated_at)
            VALUES ('applied_migrations', ?, datetime('now'))
        """, (applied_str,))

        conn.commit()
        conn.close()
        logger.info("Migrations complete – applied: %s", applied_str or "(none)")

    except Exception as e:
        logger.warning(f"Migration runner error (non-fatal): {e}")


def reset_database(confirm: bool = False) -> bool:
    """
    Delete and recreate the database.
    Requires confirm=True to prevent accidental data loss.
    
    Args:
        confirm: Must be True to proceed with reset
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not confirm:
        logger.warning("Database reset requires confirm=True parameter")
        return False
    
    try:
        # Delete existing database if it exists
        if check_database_exists():
            os.remove(DATABASE_PATH)
            logger.info(f"Deleted existing database: {DATABASE_PATH}")
        
        # Recreate database
        success = initialize_database()
        
        if success:
            logger.info("Database reset completed successfully")
        else:
            logger.error("Database reset failed during reinitialization")
            
        return success
        
    except OSError as e:
        logger.error(f"Could not delete database file: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during reset: {e}")
        return False


def verify_database_integrity() -> dict:
    """
    Verify database integrity and table structure.
    
    Returns:
        dict: Verification results with status and any issues
    """
    result = {
        'status': 'ok',
        'integrity_check': None,
        'issues': [],
        'table_counts': {}
    }
    
    if not check_database_exists():
        result['status'] = 'error'
        result['issues'].append('Database file does not exist')
        return result
    
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
        cursor = conn.cursor()
        
        # Run SQLite integrity check
        cursor.execute("PRAGMA integrity_check")
        integrity = cursor.fetchone()[0]
        result['integrity_check'] = integrity
        
        if integrity != 'ok':
            result['status'] = 'error'
            result['issues'].append(f'Integrity check failed: {integrity}')
        
        # Check required tables exist
        required_tables = ['devices', 'traffic_summary', 'alerts', 'system_config']
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        for table in required_tables:
            if table not in existing_tables:
                result['status'] = 'warning' if result['status'] == 'ok' else result['status']
                result['issues'].append(f'Missing required table: {table}')
        
        # Get row counts for existing tables
        for table in existing_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                result['table_counts'][table] = cursor.fetchone()[0]
            except:
                result['table_counts'][table] = 'error'
        
        conn.close()
        
    except sqlite3.Error as e:
        result['status'] = 'error'
        result['issues'].append(f'Database error: {e}')
    except Exception as e:
        result['status'] = 'error'
        result['issues'].append(f'Unexpected error: {e}')
    
    return result


# CLI commands reference canonical maintenance functions
# (cleanup_old_data and vacuum_database wrappers removed in Phase 3)


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def print_help():
    """Print command line help."""
    print("""
NetWatch Database Initialization Tool
=====================================

Usage: python init_db.py [command]

Commands:
  (none)    Initialize the database (create if not exists)
  --reset   Delete and recreate the database (WARNING: destroys all data)
  --info    Show database information
  --verify  Verify database integrity
  --vacuum  Optimize database (reclaim space)
  --cleanup Remove old data (traffic > 24h, resolved alerts > 7 days)
  --help    Show this help message

Examples:
  python init_db.py           # Initialize database
  python init_db.py --info    # Show database info
  python init_db.py --reset   # Reset database (with confirmation)
""")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "--help" or command == "-h":
            print_help()
            
        elif command == "--reset":
            print("WARNING: This will delete ALL data in the database!")
            confirm = input("Type 'yes' to confirm: ")
            if confirm.lower() == 'yes':
                success = reset_database(confirm=True)
                sys.exit(0 if success else 1)
            else:
                print("Reset cancelled.")
                sys.exit(0)
                
        elif command == "--info":
            info = get_database_info()
            print("\nDatabase Information:")
            print("=" * 40)
            print(f"Path: {info['path']}")
            print(f"Exists: {info['exists']}")
            if info['exists']:
                print(f"Size: {info['size_mb']} MB ({info['size_bytes']} bytes)")
                print(f"Schema Version: {info['schema_version']}")
                print(f"Created: {info['created_at']}")
                print(f"Tables: {', '.join(info['tables'])}")
            print()
            
        elif command == "--verify":
            result = verify_database_integrity()
            print("\nDatabase Verification:")
            print("=" * 40)
            print(f"Status: {result['status'].upper()}")
            print(f"Integrity: {result['integrity_check']}")
            if result['issues']:
                print("Issues:")
                for issue in result['issues']:
                    print(f"  - {issue}")
            if result['table_counts']:
                print("Table Row Counts:")
                for table, count in result['table_counts'].items():
                    print(f"  {table}: {count}")
            print()
            
        elif command == "--vacuum":
            from database.queries.maintenance import vacuum_database as _maint_vacuum
            success = _maint_vacuum()
            sys.exit(0 if success else 1)
            
        elif command == "--cleanup":
            from database.queries.maintenance import run_full_cleanup as _maint_cleanup
            result = _maint_cleanup(
                traffic_retention_days=7,
                alert_retention_days=30,
                stats_retention_days=30,
                daily_usage_retention_days=90,
            )
            total = sum(v for k, v in result.items() if k.endswith('_deleted'))
            freed = result.get('freed_mb', 0)
            print(f"Cleanup completed: {total:,} records deleted, {freed:.1f} MB freed")
            sys.exit(0)
            
        else:
            print(f"Unknown command: {command}")
            print_help()
            sys.exit(1)
    else:
        # Default: initialize database
        if check_database_exists():
            print(f"Database already exists at: {DATABASE_PATH}")
            info = get_database_info()
            print(f"Size: {info['size_mb']} MB, Tables: {len(info['tables'])}")
            print("Verifying and updating schema...")
        
        success = initialize_database()
        
        if success:
            print("Database initialization complete!")
            info = get_database_info()
            print(f"Tables: {', '.join(info['tables'])}")
        else:
            print("Database initialization failed!")
            
        sys.exit(0 if success else 1)
