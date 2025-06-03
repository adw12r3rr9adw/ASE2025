import os

def rename_files(base_path='.'):
    for root, dirs, files in os.walk(base_path):
        for filename in files:
            if "526" in filename:
                old_path = os.path.join(root, filename)
                new_filename = filename.replace("526", "test5")
                new_path = os.path.join(root, new_filename)
                try:
                    os.rename(old_path, new_path)
                    print(f"Renamed: {old_path} -> {new_path}")
                except Exception as e:
                    print(f"[ERROR] Failed to rename {old_path}: {e}")

if __name__ == "__main__":
    rename_files()
