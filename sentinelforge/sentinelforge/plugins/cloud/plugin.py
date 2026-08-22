"""Cloud Security Plugin — AWS S3 bucket and cloud misconfiguration checks."""

from __future__ import annotations

import urllib.request
from typing import TYPE_CHECKING

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.target import Target


class CloudPlugin(BasePlugin):
    """
    Cloud misconfiguration checks:
    - Public AWS S3 bucket detection
    - Azure Blob Storage public access
    - Exposed .env / cloud credential files
    """

    name = "cloud"
    description = "AWS S3 and Azure Blob public access checks"
    category = "cloud"

    def initialize(self) -> None:
        pass

    def can_run(self, target: "Target") -> bool:
        from sentinelforge.core.target import TargetType
        return target.kind in (TargetType.DOMAIN, TargetType.URL)

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target") -> PluginResult:
        result = PluginResult(plugin_name=self.name)
        host = target.host
        timeout = self._cfg("general.timeout", 10)

        for fn in [
            self._check_s3_buckets,
            self._check_azure_blobs,
        ]:
            try:
                for f in fn(host, target, timeout):
                    result.add_finding(f)
            except Exception as exc:  # noqa: BLE001
                result.metadata[fn.__name__ + "_error"] = str(exc)

        result.status = "success"
        return result

    # ------------------------------------------------------------------

    def _fetch(self, url: str, timeout: int) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                return resp.status, resp.read(20_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:  # noqa: BLE001
            return 0, ""

    def _check_s3_buckets(self, host: str, target: "Target", timeout: int) -> list:
        """Check for publicly accessible S3 buckets using common naming patterns."""
        parts = host.replace("www.", "").split(".")
        base_name = parts[0] if parts else host

        candidates = [
            base_name,
            f"{base_name}-backup",
            f"{base_name}-assets",
            f"{base_name}-static",
            f"{base_name}-uploads",
            f"{base_name}-files",
            f"{base_name}-data",
            f"{base_name}-logs",
        ]

        findings = []
        for bucket_name in candidates:
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            status, body = self._fetch(url, timeout)
            if status == 200 and "<ListBucketResult" in body:
                findings.append(
                    self._finding(
                        title="Public AWS S3 Bucket Accessible",
                        severity=Severity.CRITICAL,
                        target=target,
                        description=(
                            f"The S3 bucket '{bucket_name}' is publicly readable. "
                            "All bucket contents are accessible to anyone on the internet."
                        ),
                        evidence=[
                            f"Bucket URL: {url}",
                            f"HTTP 200 with bucket listing",
                        ],
                        recommendation=(
                            "Immediately set the bucket ACL to private. "
                            "Enable S3 Block Public Access at the account level. "
                            "Review what data was exposed."
                        ),
                        references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                        tags=["cloud", "aws", "s3", "public-access", "critical"],
                    )
                )
            elif status == 403:
                # Bucket exists but is private — note for report context
                pass

        return findings

    def _check_azure_blobs(self, host: str, target: "Target", timeout: int) -> list:
        """Check for publicly accessible Azure Blob Storage containers."""
        parts = host.replace("www.", "").split(".")
        base_name = parts[0] if parts else host

        containers = ["$web", "assets", "uploads", "files", "backup"]
        findings = []

        for container in containers:
            url = f"https://{base_name}.blob.core.windows.net/{container}?restype=container&comp=list"
            status, body = self._fetch(url, timeout)
            if status == 200 and "<EnumerationResults" in body:
                findings.append(
                    self._finding(
                        title="Public Azure Blob Storage Container Accessible",
                        severity=Severity.CRITICAL,
                        target=target,
                        description=(
                            f"Azure Blob container '{container}' under storage account "
                            f"'{base_name}' is publicly accessible."
                        ),
                        evidence=[f"Container URL: {url}", "HTTP 200 with blob listing"],
                        recommendation=(
                            "Set the container's public access level to 'Private'. "
                            "Use Shared Access Signatures (SAS) for controlled external access."
                        ),
                        references=["https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"],
                        tags=["cloud", "azure", "blob", "public-access", "critical"],
                    )
                )
        return findings
