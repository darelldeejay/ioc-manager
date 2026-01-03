try:
    from app import regenerate_feeds_from_db
    print("Import successful. Starting regeneration...")
    if regenerate_feeds_from_db():
        print("Regeneration SUCCESS")
    else:
        print("Regeneration FAILED")
except Exception as e:
    print(f"Error: {e}")
