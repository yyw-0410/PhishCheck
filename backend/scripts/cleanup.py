#!/usr/bin/env python
"""Cleanup script for removing stale unverified accounts.

Run manually or schedule via cron:
    python scripts/cleanup.py

Options:
    --days N    Delete accounts unverified for N days (default: 7)
    --dry-run   Show what would be deleted without deleting
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import SessionLocal
from app.services.auth_service import AuthService


def main():
    parser = argparse.ArgumentParser(description="Cleanup unverified accounts")
    parser.add_argument("--days", type=int, default=7, help="Days before deletion (default: 7)")
    parser.add_argument("--dry-run", action="store_true", help="Show count without deleting")
    args = parser.parse_args()
    
    db = SessionLocal()
    try:
        auth_service = AuthService(db)
        
        if args.dry_run:
            # Count without deleting
            from datetime import datetime, timedelta, timezone
            from app.models.user import User
            
            cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
            count = db.query(User).filter(
                User.is_verified == False,
                User.oauth_provider == None,
                User.created_at < cutoff
            ).count()
            
            print(f"[DRY RUN] Would delete {count} unverified account(s) older than {args.days} days")
        else:
            count = auth_service.cleanup_unverified_accounts(days_old=args.days)
            print(f"Deleted {count} unverified account(s) older than {args.days} days")
    finally:
        db.close()


if __name__ == "__main__":
    main()
