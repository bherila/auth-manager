<?php

namespace App\Http\Controllers;

use App\Http\Requests\SaveRegisteredApplicationRequest;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Services\ApplicationRegistryService;
use App\Support\StaticApplicationClients;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;

class ApplicationRegistryController extends Controller
{
    public function page(StaticApplicationClients $staticClients): Response
    {
        return response()->view('admin.applications', [
            'applications' => RegisteredApplication::with('clients')->orderBy('key')->get(),
            'clients' => PassportClient::query()->orderBy('name')->get()->filter(fn (PassportClient $client): bool => $staticClients->eligible($client)),
            'launchEnabled' => (bool) config('application-registry.launch_enabled'),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function store(SaveRegisteredApplicationRequest $request, ApplicationRegistryService $registry): JsonResponse|RedirectResponse
    {
        return $this->saved($request, $registry->save($request, $request->validated()), 201);
    }

    public function update(SaveRegisteredApplicationRequest $request, RegisteredApplication $application, ApplicationRegistryService $registry): JsonResponse|RedirectResponse
    {
        return $this->saved($request, $registry->save($request, $request->validated(), $application), 200);
    }

    private function saved(SaveRegisteredApplicationRequest $request, RegisteredApplication $application, int $status): JsonResponse|RedirectResponse
    {
        if (! $request->expectsJson()) {
            return redirect()->route('admin.applications')->with('status', 'Application registration saved. OAuth grants and application permissions were not changed.');
        }

        return response()->json(['application' => [
            'id' => $application->id,
            'key' => $application->key,
            'name' => $application->name,
            'launch_url' => $application->launch_url,
            'enabled' => $application->enabled,
            'client_ids' => $application->clients->modelKeys(),
        ]], $status)->header('Cache-Control', 'private, no-store');
    }
}
