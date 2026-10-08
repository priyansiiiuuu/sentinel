import zipfile
from pathlib import Path


def extract_zip_safely(zip_path: Path | str, extract_to: Path | str) -> Path:
    """
    Extracts a ZIP archive safely into target directory with Zip Slip protection.
    """
    destination = Path(extract_to).resolve()
    archive = Path(zip_path)

    with zipfile.ZipFile(archive, "r") as zip_ref:
        for member in zip_ref.infolist():
            # Prevent Zip Slip path traversal attack
            target_path = (destination / member.filename).resolve()
            if not target_path.is_relative_to(destination):
                raise ValueError(
                    f"Security error: Malicious zip path traversal entry '{member.filename}'"
                )

        zip_ref.extractall(destination)

    return destination
