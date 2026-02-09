<?php

namespace App\Http\Controllers\Api\V1\Connectivity;

use App\Http\Controllers\Controller;
use App\Models\Intercom;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class IntercomController extends Controller
{
    public function index(): JsonResponse
    {
        $intercoms = Intercom::with(['callServer', 'branch'])->get();

        return response()->json([
            'success' => true,
            'data' => $intercoms
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'call_server_id' => 'required|exists:call_servers,id',
            'branch_id' => 'nullable|exists:branches,id',
            'name' => 'required|string|max:255',
            'extension' => 'required|string|max:50',
            'description' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $intercom = Intercom::create($validated);
        $intercom->load(['callServer', 'branch']);

        return response()->json([
            'success' => true,
            'message' => 'Intercom created successfully',
            'data' => $intercom
        ], 201);
    }

    public function show(string $id): JsonResponse
    {
        $intercom = Intercom::with(['callServer', 'branch'])->findOrFail($id);

        return response()->json([
            'success' => true,
            'data' => $intercom
        ]);
    }

    public function update(Request $request, string $id): JsonResponse
    {
        $intercom = Intercom::findOrFail($id);

        $validated = $request->validate([
            'call_server_id' => 'required|exists:call_servers,id',
            'branch_id' => 'nullable|exists:branches,id',
            'name' => 'required|string|max:255',
            'extension' => 'required|string|max:50',
            'description' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $intercom->update($validated);
        $intercom->load(['callServer', 'branch']);

        return response()->json([
            'success' => true,
            'message' => 'Intercom updated successfully',
            'data' => $intercom
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        $intercom = Intercom::findOrFail($id);
        $intercom->delete();

        return response()->json([
            'success' => true,
            'message' => 'Intercom deleted successfully'
        ]);
    }
}
