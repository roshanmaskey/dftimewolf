# -* coding: utf-8 -*-
"""Google Cloud audit log enhancer."""
from datetime import datetime

from typing import Any


class GCPLogsEnhancer:
  """GCP Cloud audit logs enhancer."""

  _SUPPORTED_SERVICE = frozenset([
      'compute.googleapis.com',
      'storage.googleapis.com',
  ])

  def _ExtractAuthenticationInfo(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Extract attributes from `protoPayload.authenticationInfo`.

    Args:
      entry (Dict[str, Any]): Google Cloud audit log.

    Returns:
      Dict[str, Any]: Audit log with relevant fields from
        protoPayload.authenticationInfo extracted.
    """
    protopayload = entry.get('protoPayload')
    if not protopayload:
      return entry

    authentication_info = protopayload.get('authenticationInfo')
    if not authentication_info:
      return entry

    principal_email = authentication_info.get('principalEmail')
    if principal_email:
      entry['principal_email'] = principal_email

    principal_subject = authentication_info.get('principalSubject')
    if principal_subject:
      entry['principal_subject'] = principal_subject

    service_account_key_name = authentication_info.get('serviceAccountKeyName')
    if service_account_key_name:
      entry['service_account_key_name'] = service_account_key_name

    service_account_delegation_info = authentication_info.get(
        'serviceAccountDelegationInfo', [])

    impersonations = []

    for delegation_info in service_account_delegation_info:
      first_party_principal = delegation_info.get('firstPartyPrincipal', {})
      first_party_principal_email = first_party_principal.get(
          'principalEmail', '')

      if first_party_principal_email:
        impersonations.append(first_party_principal_email)
      else:
        first_party_principal_subject = first_party_principal.get(
            'principalSubject', '')
        if first_party_principal_subject:
          impersonations.append(first_party_principal_subject)

    if impersonations:
      impersonation_chain = "->".join(impersonations)
      entry['impersonations'] = impersonations
      entry['impersonation_chain'] = impersonation_chain

    return entry

  def _ExtractAuthorizationInfo(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Extract attributes from `protoPayload.authorizationInfo`.

    Args:
      entry (Dict[str, Any]): Google cloud audit log entry.

    Returns:
      Dict[str, Any]: Enhanced Google cloud audit log entry for TimeSketch.
    """
    protopayload = entry.get('protoPayload')
    if not protopayload:
      return entry

    authorization_infos = protopayload.get('authorizationInfo',[])
    if not authorization_infos:
      return entry

    permissions = []

    for authorization_info in authorization_infos:
      permission = authorization_info.get('permission', '')
      if permission:
        permissions.append(permission)

    if permissions:
      entry['permissions'] = permissions

    return entry

  def _ExtractRequestMetadata(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Extract attributes from `protoPayload.requestMetadata`.

    Args:
      entry (Dict[str, Any]): Google cloud audit log entry.

    Returns:
      Dict[str, Any]: Enhanced Google cloud audit log entry for TimeSketch.
    """
    protopayload = entry.get('protoPayload')
    if not protopayload:
      return entry

    request_metadata = protopayload.get('requestMetadata')
    if not request_metadata:
      return entry

    caller_ip = request_metadata.get('callerIp', '')
    user_agent = request_metadata.get('callerSuppliedUserAgent', '')

    entry['caller_ip'] = caller_ip
    entry['user_agent'] = user_agent

    # Adding IP address attribute for TimeSketch
    entry['ip_address'] = caller_ip

    return entry

  def _ExtractProtoPayloadStatus(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Extract attributes from `protoPayload.status`.

    Args:
      entry (Dict[str, Any]): Google cloud audit log entry.

    Returns:
      Dict[str, Any]: Enhanced Google cloud audit log entry for TimeSketch.
    """
    protopayload = entry.get('protoPayload')
    if not protopayload:
      return entry

    status = protopayload.get('status', {})
    if not status:
      # The operation completed successfully and `protoPayload.status` is null.
      entry['status_code'] = 0
      entry['status_message'] = ''
      entry['protoPayload']['protopayload_status'] = {}

      if 'status' in protopayload:
        del entry['protoPayload']['status']

      return entry

    # Handling existing status attributes code and messages.
    #
    # If `protoPayload.status.code` value is not set, it indicates the
    # the operation completed successfully.

    # If code is not numerical value, it will raise ValueError exception.
    status_code = int(status.get('code', 0))
    status_message = status.get('message', '')

    entry['status_code'] = status_code
    entry['status_message'] = status_message

    # rmaskey: Handling type issue in OpenSearch
    entry['protoPayload']['protopayload_status'] = status
    del entry['protoPayload']['status']

    return entry

  def _ExtractJsonPayloadStatus(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Extract attributes from `jsonPayload.status`.

    Args:
      entry (Dict[str, Any]): Google cloud audit log entry.

    Returns:
      Dict[str, Any]: Enhanced Google cloud audit log entry for TimeSketch.
    """
    jsonpayload = entry.get('jsonPayload')
    if not jsonpayload:
      return entry

    if 'status' in jsonpayload:
      status = jsonpayload.get('status')

      # rmaskey: Workaround to handle Type issue in OpenSearch
      entry['jsonPayload']['jsonpayload_status'] = status
      del entry['jsonPayload']['status']

    return entry

  def _ConvertToTimeSketchDateTime(self, timestamp: str) -> str:
    """Convert GCP log timestamp to TimeSketch datetime format.

    Args:
      timestamp (str): GCP log timestamp.

    Returns:
      str: Timestamp as TimeSketch datetime.
    """
    try:
      datetime_second = timestamp.split('.')[0] + 'Z'
      ts_datetime = datetime.strptime(
          datetime_second,
          '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')
    except ValueError:
      ts_datetime = datetime.strptime(
          timestamp,
          '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')

    return ts_datetime

  def _AddTimeSketchFields(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Add mandatory fields required for TimeSketch.

    Args:
      entry (dict[str, Any]): GCP audit log entry.

    Returns:
      dict[str, Any]: GCP audit log with required TimeSketch attributes.
    """
    if not entry:
      return entry

    timestamp = entry.get('timestamp')
    ts_datetime = self._ConvertToTimeSketchDateTime(timestamp)

    entry['datetime'] = ts_datetime
    entry['timestamp_desc'] = 'Event time'

    # Add TimeSketch message attribute
    principal_email = entry.get('principal_email', 'unknown')
    resource_name = entry.get('resource_name', 'unknown')
    method_name = entry.get('method_name', 'unknown')

    status_code = entry.get('status_code', -1)
    status_message = entry.get('status_message', '')

    message = (f'Principal {principal_email} performed the operation '
        f'{method_name} on the resource {resource_name}')

    if status_code == 0:
      message = f'{message} which was successful.'
    elif status_code > 0:
      message = f'{message} which failed.'
    else:
      if status_message:
        message = status_message
      else:
        message = f'{message}.'

    entry['message'] = message

    return entry

  def _ProtoPayloadCommonExtraction(
      self, entry: dict[str, Any]) -> dict[str, Any]:
    """Extract common attributes from `protoPayload`.

    Args:
      entry (Dict[str, Any]): Google cloud audit log entry.

    Returns:
      Dict[str, Any]: Enhanced Google cloud audit log entry for TimeSketch.
    """
    if not entry:
      return entry

    protopayload = entry.get('protoPayload')
    if not protopayload:
      return entry

    resource_name = protopayload.get('resourceName', '')
    method_name = protopayload.get('methodName', '')

    entry['resource_name'] = resource_name
    entry['method_name'] = method_name

    entry = self._ExtractAuthenticationInfo(entry)
    entry = self._ExtractAuthorizationInfo(entry)
    entry = self._ExtractRequestMetadata(entry)
    entry = self._ExtractProtoPayloadStatus(entry)

    return entry

  def Process(self, entry: dict[str, Any]) -> dict[str, Any]:
    """Executes GCPLogs enhancer modules."""
    jsonpayload = entry.get('jsonPayload')
    if jsonpayload:
      entry = self._ExtractJsonPayloadStatus(entry)

    protopayload = entry.get('protoPayload')
    if protopayload:
      # Run common extractions
      entry = self._ProtoPayloadCommonExtraction(entry)

    entry = self._AddTimeSketchFields(entry)

    return entry
