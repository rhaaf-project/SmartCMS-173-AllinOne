<?php

namespace App\Http\Controllers\Api\V1\Connectivity;

use App\Http\Controllers\Controller;
use App\Models\Trunk;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class TrunkController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = Trunk::query()->with('callServer');

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('name', 'like', "%{$search}%")
                ->orWhere('channelid', 'like', "%{$search}%");
        }

        $trunks = $query->paginate($request->get('per_page', 15));

        return response()->json($trunks);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:100',
            'call_server_id' => 'nullable|exists:call_servers,id',
            'sip_server' => 'required_without:host|string',
            'outcid' => 'nullable|string',
            'transport' => 'required|in:udp,tcp,tls',
            'context' => 'required|string',
            'maxchans' => 'integer',
            'disabled' => 'boolean',
        ]);

        $trunk = Trunk::create($validated);

        return response()->json(['message' => 'Trunk created successfully', 'data' => $trunk], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(Trunk $trunk): JsonResponse
    {
        return response()->json($trunk);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Trunk $trunk): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'sometimes|string|max:100',
            'call_server_id' => 'nullable|exists:call_servers,id',
            'sip_server' => 'sometimes|string',
            'outcid' => 'nullable|string',
            'transport' => 'sometimes|in:udp,tcp,tls',
            'maxchans' => 'integer',
            'disabled' => 'boolean',
        ]);

        $trunk->update($validated);

        return response()->json(['message' => 'Trunk updated successfully', 'data' => $trunk]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Trunk $trunk): JsonResponse
    {
        $trunk->delete();
        return response()->json(['message' => 'Trunk deleted successfully']);
    }
}
