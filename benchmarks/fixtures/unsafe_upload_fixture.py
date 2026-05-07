"""Intentionally vulnerable fixture for GuardGraph static-analysis tests only.

This file is NOT an application route and is NOT imported by the test app.
It exists only as a minimal benchmark fixture for detecting unsafe upload
boundaries such as CWE-434 / CWE-284.
"""

from fastapi import APIRouter, File, UploadFile

router = APIRouter(prefix="/api/plugins", tags=["plugins"])


class PluginService:
    async def upload_my_plugin(self, plugin_file: UploadFile, user: str | None = None):
        return {"filename": plugin_file.filename, "user": user}

    def refresh_plugins(self):
        return {"status": "refreshed"}


plugin_service = PluginService()


@router.post("/upload")
async def plugin_upload(plugin_file: UploadFile = File(...), user: str | None = None):
    """Intentionally unsafe upload boundary for static analysis benchmarking.

    Missing by design:
    - authentication boundary
    - role/permission boundary
    - upload extension/content/size validation
    """
    await plugin_service.upload_my_plugin(plugin_file, user)
    plugin_service.refresh_plugins()
    return {"status": "uploaded"}
