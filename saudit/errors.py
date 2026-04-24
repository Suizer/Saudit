class SAUDITError(Exception):
    pass


class ScanError(SAUDITError):
    pass


class ValidationError(SAUDITError):
    pass


class ConfigLoadError(SAUDITError):
    pass


class HttpCompareError(SAUDITError):
    pass


class DirectoryCreationError(SAUDITError):
    pass


class DirectoryDeletionError(SAUDITError):
    pass


class NTLMError(SAUDITError):
    pass


class InteractshError(SAUDITError):
    pass


class WordlistError(SAUDITError):
    pass


class CurlError(SAUDITError):
    pass


class PresetNotFoundError(SAUDITError):
    pass


class EnableModuleError(SAUDITError):
    pass


class EnableFlagError(SAUDITError):
    pass


class SAUDITArgumentError(SAUDITError):
    pass


class PresetConditionError(SAUDITError):
    pass


class PresetAbortError(PresetConditionError):
    pass


class SAUDITEngineError(SAUDITError):
    pass


class WebError(SAUDITEngineError):
    pass


class DNSError(SAUDITEngineError):
    pass


class ExcavateError(SAUDITError):
    pass
