from _typeshed import Incomplete
from collections.abc import Generator
from ipalib.capabilities import client_has_capability as client_has_capability
from ipalib.constants import TYPE_ERROR as TYPE_ERROR
from ipalib.text import Gettext as Gettext, NGettext as NGettext

unicode = str

def add_message(version, result, message) -> None: ...
def process_message_arguments(
    obj,
    format: Incomplete | None = ...,
    message: Incomplete | None = ...,
    **kw,
): ...

class PublicMessage(UserWarning):
    def __init__(
        self,
        format: Incomplete | None = ...,
        message: Incomplete | None = ...,
        **kw,
    ) -> None: ...
    errno: int
    format: Incomplete
    def to_dict(self): ...

class VersionMissing(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class ForwardersWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSSECWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class OptionDeprecatedWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class OptionSemanticChangedWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSServerValidationWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSServerDoesNotSupportDNSSECWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class ForwardzoneIsNotEffectiveWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSServerDoesNotSupportEDNS0Warning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSSECValidationFailingWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class KerberosTXTRecordCreationFailure(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class KerberosTXTRecordDeletionFailure(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSSECMasterNotInstalled(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSSuspiciousRelativeName(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class CommandDeprecatedWarning(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class ExternalCommandOutput(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class SearchResultTruncated(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class BrokenTrust(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class ResultFormattingError(PublicMessage):
    type: str
    errno: int

class FailedToRemoveHostDNSRecords(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSForwardPolicyConflictWithEmptyZone(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSUpdateOfSystemRecordFailed(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class DNSUpdateNotIPAManagedZone(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class AutomaticDNSRecordsUpdateFailed(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class ServiceRestartRequired(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class LocationWithoutDNSServer(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class ServerRemovalInfo(PublicMessage):
    errno: int
    type: str

class ServerRemovalWarning(PublicMessage):
    errno: int
    type: str

class CertificateInvalid(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class FailedToAddHostDNSRecords(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class LightweightCACertificateNotAvailable(PublicMessage):
    errno: int
    type: str
    format: Incomplete

class MissingTargetAttributesinPermission(PublicMessage):
    errno: int
    type: str
    format: Incomplete

def iter_messages(variables, base) -> Generator[Incomplete, None, None]: ...

public_messages: Incomplete

def print_report(label, classes) -> None: ...
