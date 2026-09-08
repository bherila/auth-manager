<?php

namespace App\Http\Requests;

use App\Support\AuthManagerProfile;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use InvalidArgumentException;

class SaveRegisteredApplicationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->canLogin() && $this->user()?->hasRole('admin');
    }

    protected function prepareForValidation(): void
    {
        if (! $this->expectsJson() && ! $this->filled('client_ids')) {
            $this->merge(['client_ids' => []]);
        }
    }

    public function rules(): array
    {
        return [
            'key' => $this->route('application') === null
                ? ['required', 'string', 'max:64', 'regex:/^[a-z][a-z0-9-]*$/', Rule::unique('registered_applications', 'key')]
                : ['prohibited'],
            'name' => ['required', 'string', 'max:255'],
            'launch_url' => ['required', 'string', 'max:2048', function (string $attribute, mixed $value, Closure $fail): void {
                try {
                    AuthManagerProfile::validatedAbsoluteUrl($value, 'Launch URL');
                    if (strtolower((string) parse_url($value, PHP_URL_SCHEME)) !== 'https') {
                        throw new InvalidArgumentException;
                    }
                } catch (InvalidArgumentException) {
                    $fail('The launch URL must be an absolute HTTPS URL without credentials, query, or fragment.');
                }
            }],
            'enabled' => ['required', 'boolean'],
            'client_ids' => ['present', 'array', 'max:100'],
            'client_ids.*' => ['required', 'string', 'uuid', 'distinct'],
        ];
    }
}
