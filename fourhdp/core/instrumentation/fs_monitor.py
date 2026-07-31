import os
from typing import Dict, List, NamedTuple

class FileMetadata(NamedTuple):
    size: int
    mtime: float

class FileSystemMonitor:
    """
    Monitors file system changes by taking snapshots of directory states.
    """
    
    def capture_snapshot(self, path: str = ".") -> Dict[str, FileMetadata]:
        """
        Recursively lists files in the directory and captures their metadata.
        Keys are paths relative to the root 'path' argument.
        
        Args:
            path: Root directory to monitor. Defaults to current working directory.
            
        Returns:
            Dict[str, FileMetadata]: Map of relative file paths to their metadata.
        """
        snapshot = {}
        target_path = os.path.abspath(path)
        
        for root, _, files in os.walk(target_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, start=target_path)
                try:
                    stats = os.stat(full_path)
                    snapshot[rel_path] = FileMetadata(
                        size=stats.st_size,
                        mtime=stats.st_mtime
                    )
                except OSError:
                    # File might have been deleted or permission denied during walk
                    continue
                    
        return snapshot

    def diff_snapshots(self, before: Dict[str, FileMetadata], after: Dict[str, FileMetadata]) -> List[str]:
        """
        Compares two snapshots and identifies created, deleted, and modified files.
        
        Args:
            before: Snapshot taken before execution.
            after: Snapshot taken after execution.
            
        Returns:
            List[str]: List of change descriptions.
        """
        changes = []
        
        before_keys = set(before.keys())
        after_keys = set(after.keys())
        
        # Detected Creations
        created = after_keys - before_keys
        for path in created:
            changes.append(f"Created: {path}")
            
        # Detect Deletions
        deleted = before_keys - after_keys
        for path in deleted:
            changes.append(f"Deleted: {path}")
            
        # Detect Modifications
        common = before_keys.intersection(after_keys)
        for path in common:
            b_meta = before[path]
            a_meta = after[path]
            
            if b_meta.size != a_meta.size or b_meta.mtime != a_meta.mtime:
                changes.append(f"Modified: {path}")
                
        return sorted(changes)

    def _get_rel_path(self, path: str) -> str:
        """Helper to get relative path for cleaner output."""
        return path
