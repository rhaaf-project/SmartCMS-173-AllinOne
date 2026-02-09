<?php

namespace App\Http\Controllers\Api\V1\Sbc;

use App\Http\Controllers\Controller;
use App\Models\Sbc;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use Throwable;

class SbcController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = Sbc::query()->with('callServer');

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('name', 'like', "%{$search}%")
                ->orWhere('sip_server', 'like', "%{$search}%");
        }

        $sbcs = $query->paginate($request->get('per_page', 15));

        return response()->json($sbcs);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request): JsonResponse
    {
        try {
            $validated = $request->validate([
                'name' => 'required|string|max:100',
                'call_server_id' => 'nullable',
                'sip_server' => 'required|string',
                'sip_server_port' => 'nullable|integer',
                'transport' => 'nullable|string',
                'context' => 'nullable|string',
                'codecs' => 'nullable|string',
                'dtmfmode' => 'nullable|string',
                'registration' => 'nullable|string',
                'auth_username' => 'nullable|string',
                'secret' => 'nullable|string',
                'outcid' => 'nullable|string',
                'maxchans' => 'nullable|integer',
                'qualify' => 'nullable|boolean',
                'qualify_frequency' => 'nullable|integer',
                'description' => 'nullable|string',
                'disabled' => 'nullable|boolean',
            ]);

            // Ensure defaults if missing
            $validated['sip_server_port'] = $validated['sip_server_port'] ?? 5060;
            $validated['maxchans'] = $validated['maxchans'] ?? 2;
            $validated['transport'] = $validated['transport'] ?? 'udp';
            $validated['context'] = $validated['context'] ?? 'from-pstn';
            $validated['codecs'] = $validated['codecs'] ?? 'ulaw,alaw';
            $validated['dtmfmode'] = $validated['dtmfmode'] ?? 'auto';
            $validated['registration'] = $validated['registration'] ?? 'none';

            $sbc = Sbc::create($validated);

            return response()->json(['message' => 'SBC created successfully', 'data' => $sbc], 201);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json(['error' => 'Validation failed', 'errors' => $e->errors()], 422);
        } catch (Throwable $e) {
            Log::error('SBC Creation Error: ' . $e->getMessage());
            return response()->json(['error' => 'Database error: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(Sbc $sbc): JsonResponse
    {
        return response()->json($sbc);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Sbc $sbc): JsonResponse
    {
        try {
            $validated = $request->validate([
                'name' => 'sometimes|string|max:100',
                'call_server_id' => 'nullable',
                'sip_server' => 'sometimes|string',
                'sip_server_port' => 'nullable|integer',
                'transport' => 'nullable|string',
                'context' => 'nullable|string',
                'codecs' => 'nullable|string',
                'dtmfmode' => 'nullable|string',
                'registration' => 'nullable|string',
                'auth_username' => 'nullable|string',
                'secret' => 'nullable|string',
                'outcid' => 'nullable|string',
                'maxchans' => 'nullable|integer',
                'qualify' => 'nullable|boolean',
                'qualify_frequency' => 'nullable|integer',
                'description' => 'nullable|string',
                'disabled' => 'nullable|boolean',
            ]);

            $sbc->update($validated);

            return response()->json(['message' => 'SBC updated successfully', 'data' => $sbc]);
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json(['error' => 'Validation failed', 'errors' => $e->errors()], 422);
        } catch (Throwable $e) {
            return response()->json(['error' => 'Database error: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Sbc $sbc): JsonResponse
    {
        $sbc->delete();
        return response()->json(['message' => 'SBC deleted successfully']);
    }
}
