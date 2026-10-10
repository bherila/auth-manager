{{-- One user action: minted as the form renders, so resubmitting this form repeats the same operation. --}}
<input type="hidden" name="operation_id" value="{{ \BWH\Auth\OAuth\DelegatedAccess\DelegatedContract::operationId() }}">
