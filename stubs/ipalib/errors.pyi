from _typeshed import Incomplete

class PrivateError(Exception):
    format: str
    msg: Incomplete
    kw: Incomplete
    def __init__(self, **kw) -> None: ...
    @property
    def message(self): ...

class SubprocessError(PrivateError):
    format: str

class PluginSubclassError(PrivateError):
    format: str

class PluginDuplicateError(PrivateError):
    format: str

class PluginOverrideError(PrivateError):
    format: str

class PluginMissingOverrideError(PrivateError):
    format: str

class SkipPluginModule(PrivateError):
    format: str

class PluginsPackageError(PrivateError):
    format: str

class PluginModuleError(PrivateError):
    format: str

class KrbPrincipalWrongFAST(PrivateError):
    format: str

class PublicError(Exception):
    def __init__(
        self,
        format: Incomplete | None = ...,
        message: Incomplete | None = ...,
        **kw,
    ) -> None: ...
    errno: int
    rval: int
    format: Incomplete
    @property
    def message(self): ...

class VersionError(PublicError):
    errno: int
    format: Incomplete

class UnknownError(PublicError):
    errno: int
    format: Incomplete

class InternalError(PublicError):
    errno: int
    format: Incomplete
    def __init__(self, message: Incomplete | None = ...) -> None: ...

class ServerInternalError(PublicError):
    errno: int
    format: Incomplete

class CommandError(PublicError):
    errno: int
    format: Incomplete

class ServerCommandError(PublicError):
    errno: int
    format: Incomplete

class NetworkError(PublicError):
    errno: int
    format: Incomplete

class ServerNetworkError(PublicError):
    errno: int
    format: Incomplete

class JSONError(PublicError):
    errno: int
    format: Incomplete

class XMLRPCMarshallError(PublicError):
    errno: int
    format: Incomplete

class RefererError(PublicError):
    errno: int
    format: Incomplete

class EnvironmentError(PublicError):
    errno: int

class SystemEncodingError(PublicError):
    errno: int
    format: Incomplete

class AuthenticationError(PublicError):
    errno: int

class KerberosError(AuthenticationError):
    errno: int
    format: Incomplete

class CCacheError(KerberosError):
    errno: int
    format: Incomplete

class ServiceError(KerberosError):
    errno: int
    format: Incomplete

class NoCCacheError(KerberosError):
    errno: int
    format: Incomplete

class TicketExpired(KerberosError):
    errno: int
    format: Incomplete

class BadCCachePerms(KerberosError):
    errno: int
    format: Incomplete

class BadCCacheFormat(KerberosError):
    errno: int
    format: Incomplete

class CannotResolveKDC(KerberosError):
    errno: int
    format: Incomplete

class SessionError(AuthenticationError):
    errno: int
    format: Incomplete

class InvalidSessionPassword(SessionError):
    errno: int
    format: Incomplete

class PasswordExpired(InvalidSessionPassword):
    errno: int

class KrbPrincipalExpired(SessionError):
    errno: int

class UserLocked(SessionError):
    errno: int

class AuthorizationError(PublicError):
    errno: int

class ACIError(AuthorizationError):
    errno: int
    format: Incomplete

class InvocationError(PublicError):
    errno: int

class EncodingError(InvocationError):
    errno: int

class BinaryEncodingError(InvocationError):
    errno: int

class ZeroArgumentError(InvocationError):
    errno: int
    format: Incomplete

class MaxArgumentError(InvocationError):
    errno: int
    def __init__(self, message: Incomplete | None = ..., **kw) -> None: ...

class OptionError(InvocationError):
    errno: int

class OverlapError(InvocationError):
    errno: int
    format: Incomplete

class RequirementError(InvocationError):
    errno: int
    format: Incomplete

class ConversionError(InvocationError):
    errno: int
    format: Incomplete

class ValidationError(InvocationError):
    errno: int
    format: Incomplete

class NoSuchNamespaceError(InvocationError):
    errno: int
    format: Incomplete

class PasswordMismatch(InvocationError):
    errno: int
    format: Incomplete

class NotImplementedError(InvocationError):
    errno: int
    format: Incomplete

class NotConfiguredError(InvocationError):
    errno: int
    format: Incomplete

class PromptFailed(InvocationError):
    errno: int
    format: Incomplete

class DeprecationError(InvocationError):
    errno: int
    format: Incomplete

class NotAForestRootError(InvocationError):
    errno: int
    format: Incomplete

class ExecutionError(PublicError):
    errno: int

class NotFound(ExecutionError):
    errno: int
    rval: int
    format: Incomplete

class DuplicateEntry(ExecutionError):
    errno: int
    format: Incomplete

class HostService(ExecutionError):
    errno: int
    format: Incomplete

class MalformedServicePrincipal(ExecutionError):
    errno: int
    format: Incomplete

class RealmMismatch(ExecutionError):
    errno: int
    format: Incomplete

class RequiresRoot(ExecutionError):
    errno: int
    format: Incomplete

class AlreadyPosixGroup(ExecutionError):
    errno: int
    format: Incomplete

class MalformedUserPrincipal(ExecutionError):
    errno: int
    format: Incomplete

class AlreadyActive(ExecutionError):
    errno: int
    format: Incomplete

class AlreadyInactive(ExecutionError):
    errno: int
    format: Incomplete

class HasNSAccountLock(ExecutionError):
    errno: int
    format: Incomplete

class NotGroupMember(ExecutionError):
    errno: int
    format: Incomplete

class RecursiveGroup(ExecutionError):
    errno: int
    format: Incomplete

class AlreadyGroupMember(ExecutionError):
    errno: int
    format: Incomplete

class Base64DecodeError(ExecutionError):
    errno: int
    format: Incomplete

class RemoteRetrieveError(ExecutionError):
    errno: int
    format: Incomplete

class SameGroupError(ExecutionError):
    errno: int
    format: Incomplete

class DefaultGroupError(ExecutionError):
    errno: int
    format: Incomplete

class ManagedGroupError(ExecutionError):
    errno: int
    format: Incomplete

class ManagedPolicyError(ExecutionError):
    errno: int
    format: Incomplete

class FileError(ExecutionError):
    errno: int
    format: Incomplete

class NoCertificateError(ExecutionError):
    errno: int
    format: Incomplete

class ManagedGroupExistsError(ExecutionError):
    errno: int
    format: Incomplete

class ReverseMemberError(ExecutionError):
    errno: int
    format: Incomplete

class AttrValueNotFound(ExecutionError):
    errno: int
    rval: int
    format: Incomplete

class SingleMatchExpected(ExecutionError):
    errno: int
    rval: int
    format: Incomplete

class AlreadyExternalGroup(ExecutionError):
    errno: int
    format: Incomplete

class ExternalGroupViolation(ExecutionError):
    errno: int
    format: Incomplete

class PosixGroupViolation(ExecutionError):
    errno: int
    format: Incomplete

class EmptyResult(NotFound):
    errno: int

class InvalidDomainLevelError(ExecutionError):
    errno: int
    format: Incomplete

class ServerRemovalError(ExecutionError):
    errno: int
    format: Incomplete

class OperationNotSupportedForPrincipalType(ExecutionError):
    errno: int
    format: Incomplete

class HTTPRequestError(RemoteRetrieveError):
    errno: int
    format: Incomplete

class RedundantMappingRule(SingleMatchExpected):
    errno: int
    format: Incomplete

class CSRTemplateError(ExecutionError):
    errno: int
    format: Incomplete

class AlreadyContainsValueError(ExecutionError):
    errno: int
    format: Incomplete

class BuiltinError(ExecutionError):
    errno: int

class HelpError(BuiltinError):
    errno: int
    format: Incomplete

class LDAPError(ExecutionError):
    errno: int

class MidairCollision(ExecutionError):
    errno: int
    format: Incomplete

class EmptyModlist(ExecutionError):
    errno: int
    format: Incomplete

class DatabaseError(ExecutionError):
    errno: int
    format: Incomplete

class LimitsExceeded(ExecutionError):
    errno: int
    format: Incomplete

class ObjectclassViolation(ExecutionError):
    errno: int
    format: Incomplete

class NotAllowedOnRDN(ExecutionError):
    errno: int
    format: Incomplete

class OnlyOneValueAllowed(ExecutionError):
    errno: int
    format: Incomplete

class InvalidSyntax(ExecutionError):
    errno: int
    format: Incomplete

class BadSearchFilter(ExecutionError):
    errno: int
    format: Incomplete

class NotAllowedOnNonLeaf(ExecutionError):
    errno: int
    format: Incomplete

class DatabaseTimeout(DatabaseError):
    errno: int
    format: Incomplete

class TaskTimeout(DatabaseError):
    errno: int
    format: Incomplete

class TimeLimitExceeded(LimitsExceeded):
    errno: int
    format: Incomplete

class SizeLimitExceeded(LimitsExceeded):
    errno: int
    format: Incomplete

class AdminLimitExceeded(LimitsExceeded):
    errno: int
    format: Incomplete

class CertificateError(ExecutionError):
    errno: int

class CertificateOperationError(CertificateError):
    errno: int
    format: Incomplete

class CertificateFormatError(CertificateError):
    errno: int
    format: Incomplete

class MutuallyExclusiveError(ExecutionError):
    errno: int
    format: Incomplete

class NonFatalError(ExecutionError):
    errno: int
    format: Incomplete

class AlreadyRegisteredError(ExecutionError):
    errno: int
    format: Incomplete

class NotRegisteredError(ExecutionError):
    errno: int
    format: Incomplete

class DependentEntry(ExecutionError):
    errno: int
    format: Incomplete

class LastMemberError(ExecutionError):
    errno: int
    format: Incomplete

class ProtectedEntryError(ExecutionError):
    errno: int
    format: Incomplete

class CertificateInvalidError(CertificateError):
    errno: int
    format: Incomplete

class SchemaUpToDate(ExecutionError):
    errno: int
    format: Incomplete

class DNSError(ExecutionError):
    errno: int

class DNSNotARecordError(DNSError):
    errno: int
    format: Incomplete

class DNSDataMismatch(DNSError):
    errno: int
    format: Incomplete

class DNSResolverError(DNSError):
    errno: int
    format: Incomplete

class TrustError(ExecutionError):
    errno: int

class TrustTopologyConflictError(TrustError):
    errno: int
    format: Incomplete

class GenericError(PublicError):
    errno: int

public_errors: Incomplete
errors_by_code: Incomplete
