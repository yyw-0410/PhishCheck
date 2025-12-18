#!/usr/bin/env python
"""Cleanup script for removing stale database records.

Run manually or schedule via cron:
    python scripts/cleanup.py

Options:
    --days N         Delete unverified accounts older than N days (default: 7)
    --guest-days N   Delete guest rate limit records older than N days (default: 1)
    --dry-run        Show what would be deleted without deleting
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import SessionLocal
from app.services.auth_service import AuthService


def main():
    parser = argparse.ArgumentParser(description="Cleanup stale database records")
    parser.add_argument("--days", type=int, default=7, help="Days before deleting unverified accounts (default: 7)")
    parser.add_argument("--guest-days", type=int, default=1, help="Days before deleting guest rate limit records (default: 1)")
    parser.add_argument("--dry-run", action="store_true", help="Show count without deleting")
    args = parser.parse_args()
    
    db = SessionLocal()
    try:
        auth_service = AuthService(db)
        
        if args.dry_run:
            # Count without deleting
            from datetime import datetime, timedelta, timezone
            from app.models.user import User, GuestRateLimit
            
            # Unverified accounts
            user_cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
            user_count = db.query(User).filter(
                User.is_verified == False,
                User.oauth_provider == None,
                User.created_at < user_cutoff
            ).count()
            
            # Guest rate limits
            guest_cutoff = datetime.now(timezone.utc) - timedelta(days=args.guest_days)
            guest_count = db.query(GuestRateLimit).filter(
                GuestRateLimit.last_analysis_date < guest_cutoff
            ).count()
            
            print(f"[DRY RUN] Would delete {user_count} unverified account(s) older than {args.days} days")
            print(f"[DRY RUN] Would delete {guest_count} guest rate limit record(s) older than {args.guest_days} day(s)")
        else:
            # Delete unverified accounts
            user_count = auth_service.cleanup_unverified_accounts(days_old=args.days)
            print(f"Deleted {user_count} unverified account(s) older than {args.days} days")
            
            # Delete old guest rate limits
            guest_count = auth_service.cleanup_old_guest_records(days_old=args.guest_days)
            print(f"Deleted {guest_count} guest rate limit record(s) older than {args.guest_days} day(s)")
    finally:
        db.close()


if __name__ == "__main__":
    main()
