<?php

namespace App\Http\Controllers\Api\V1\Connectivity;

use App\Http\Controllers\Controller;
use App\Models\InboundRoute;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class InboundRouteController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = InboundRoute::query()->with(['trunk', 'destinationExtension']);

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('did_number', 'like', "%{$search}%")
                ->orWhere('description', 'like', "%{$search}%");
        }

        $routes = $query->paginate($request->get('per_page', 15));

        return response()->json($routes);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'did_number' => 'required|string|max:50',
            'description' => 'nullable|string',
            'trunk_id' => 'nullable|exists:trunks,id',
            'destination_type' => 'required|in:extension,ring_group,ivr,voicemail,hangup',
            'destination_id' => 'required_if:destination_type,extension,ring_group,ivr,voicemail|integer',
            'cid_filter' => 'nullable|string',
            'priority' => 'integer',
            'is_active' => 'boolean',
        ]);

        $route = InboundRoute::create($validated);

        return response()->json(['message' => 'Inbound Route created successfully', 'data' => $route], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(InboundRoute $inboundRoute): JsonResponse
    {
        $inboundRoute->load(['trunk', 'destinationExtension']);
        return response()->json($inboundRoute);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, InboundRoute $inboundRoute): JsonResponse
    {
        $validated = $request->validate([
            'did_number' => 'sometimes|string|max:50',
            'description' => 'nullable|string',
            'trunk_id' => 'nullable|exists:trunks,id',
            'destination_type' => 'sometimes|in:extension,ring_group,ivr,voicemail,hangup',
            'destination_id' => 'nullable|integer',
            'cid_filter' => 'nullable|string',
            'priority' => 'integer',
            'is_active' => 'boolean',
        ]);

        $inboundRoute->update($validated);

        return response()->json(['message' => 'Inbound Route updated successfully', 'data' => $inboundRoute]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(InboundRoute $inboundRoute): JsonResponse
    {
        $inboundRoute->delete();
        return response()->json(['message' => 'Inbound Route deleted successfully']);
    }
}
