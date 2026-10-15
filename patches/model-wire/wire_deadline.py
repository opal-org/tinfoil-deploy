"""Shared local monotonic budgets for the accepted nested model deadline policy."""
import math
import re
import time


DEADLINE_POLICY_SHA256 = '3098070ff147a92afab6609b5f67a98a5784fe0a5eccc8de0703b9ecd4b083ec'
BUDGET_HEADER = 'X-Opal-Remaining-Budget-Ms'
OPERATION_SECONDS = 120
PROVIDER_SECONDS = 110
PROXY_SECONDS = 105
GATEWAY_SECONDS = 100
OPERATION_MARGIN_SECONDS = 10
HOP_MARGIN_SECONDS = 5
PROVIDER_MAX_MS = 110000
PROXY_MAX_MS = 105000
OPERATIONAL_SECONDS = 3


class DeadlineBudgetError(ValueError):
    pass


def require_cap(value, expected, *, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value != expected or value <= 0:
        raise DeadlineBudgetError('Incompatible ' + name + ' deadline cap')


def parse_budget_header(headers, *, maximum_ms):
    values = headers.get_all(BUDGET_HEADER, [])
    if len(values) != 1 or re.fullmatch(r'[0-9]{6}', values[0]) is None:
        raise DeadlineBudgetError('Exactly one fixed-width remaining budget required')
    milliseconds = int(values[0])
    if not 1 <= milliseconds <= maximum_ms:
        raise DeadlineBudgetError('Remaining budget outside policy bounds')
    return milliseconds


def derive_deadline(caller_ms, *, received_at, cap_seconds, margin_seconds):
    if type(caller_ms) is not int or caller_ms <= 0:
        raise DeadlineBudgetError('Positive integer caller budget required')
    if any(type(value) not in (int, float) or not math.isfinite(value)
           for value in (received_at, cap_seconds, margin_seconds)):
        raise DeadlineBudgetError('Finite local deadline parameters required')
    if cap_seconds <= 0 or margin_seconds < 0:
        raise DeadlineBudgetError('Invalid local deadline parameters')
    deadline = min(received_at + cap_seconds, received_at + caller_ms / 1000 - margin_seconds)
    if deadline <= received_at:
        raise DeadlineBudgetError('Remaining caller budget cannot cover hop margin')
    remaining_seconds(deadline)
    return deadline


def remaining_seconds(deadline):
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise DeadlineBudgetError('Finite monotonic deadline required')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DeadlineBudgetError('Local monotonic deadline exhausted')
    return remaining


def format_budget_header(deadline, *, maximum_ms):
    milliseconds = math.floor(remaining_seconds(deadline) * 1000)
    if not 1 <= milliseconds <= maximum_ms:
        raise DeadlineBudgetError('Dispatch budget outside policy bounds')
    return f'{milliseconds:06d}'


def provider_deadline(operation_deadline, *, started_at):
    if any(type(value) not in (int, float) or not math.isfinite(value)
           for value in (operation_deadline, started_at)):
        raise DeadlineBudgetError('Finite operation deadline required')
    deadline = min(started_at + PROVIDER_SECONDS, operation_deadline - OPERATION_MARGIN_SECONDS)
    if deadline <= started_at:
        raise DeadlineBudgetError('Operation budget cannot cover provider margin')
    remaining_seconds(deadline)
    return deadline
