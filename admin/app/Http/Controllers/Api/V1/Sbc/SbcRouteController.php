<?php

namespace App\Http\Controllers\Api\V1\Sbc;

use App\Http\Controllers\Controller;
use App\Models\SbcRoute;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class SbcRouteController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = SbcRoute::query()->with('sbc');

        if ($request->has('sbc_id')) {
            $query->where('sbc_id', $request->sbc_id);
        }

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('pattern', 'like', "%{$search}%")
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
            'sbc_id' => 'required|exists:sbcs,id',
            'pattern' => 'required|string|max:100',
            'prefix' => 'nullable|string|max:50',
            'strip' => 'integer|min:0',
            'priority' => 'integer',
            'description' => 'nullable|string',
        ]);

        $route = SbcRoute::create($validated);

        return response()->json(['message' => 'SBC Route created successfully', 'data' => $route], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(SbcRoute $sbcRoute): JsonResponse
    {
        $sbcRoute->load('sbc');
        return response()->json($sbcRoute);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, SbcRoute $sbcRoute): JsonResponse
    {
        $validated = $request->validate([
            'pattern' => 'sometimes|string|max:100',
            'prefix' => 'nullable|string|max:50',
            'strip' => 'integer|min:0',
            'priority' => 'integer',
            'description' => 'nullable|string',
        ]);

        $sbcRoute->update($validated);

        return response()->json(['message' => 'SBC Route updated successfully', 'data' => $sbcRoute]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(SbcRoute $sbcRoute): JsonResponse
    {
        $sbcRoute->delete();
        return response()->json(['message' => 'SBC Route deleted successfully']);
    }
}
