"""Remote Diagnostics and Configuration"""
from knxmap.messages import KnxMessage
#TODO: Implement message types


class KnxRemoteDiagnosticRequest(KnxMessage):
    pass


class KnxRemoteDiagnosticResponse(KnxMessage):
    pass


class KnxRemoteBasicConfigurationRequest(KnxMessage):
    pass


class KnxRemoteResetRequest(KnxMessage):
    pass
