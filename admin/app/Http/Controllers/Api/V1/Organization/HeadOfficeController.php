<?php

namespace App\Http\Controllers\Api\V1\Organization;

use App\Http\Controllers\Controller;
use App\Models\HeadOffice;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class HeadOfficeController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = HeadOffice::query()->with('customer')->withCount(['branches', 'callServers']);

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('name', 'like', "%{$search}%")
                ->orWhere('code', 'like', "%{$search}%")
                ->orWhere('city', 'like', "%{$search}%");
        }

        if ($request->has('customer_id')) {
            $query->where('customer_id', $request->customer_id);
        }

        $headOffices = $query->paginate($request->get('per_page', 15));

        return response()->json($headOffices);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'customer_id' => 'required|exists:customers,id',
            'name' => 'required|string|max:100',
            'code' => 'nullable|string|max:20',
            'type' => 'required|in:basic,ha,fo',
            'country' => 'nullable|string|max:50',
            'province' => 'nullable|string|max:50',
            'city' => 'nullable|string|max:50',
            'district' => 'nullable|string|max:50',
            'address' => 'nullable|string',
            'contact_name' => 'nullable|string|max:100',
            'contact_phone' => 'nullable|string|max:30',
            'description' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $headOffice = HeadOffice::create($validated);

        return response()->json(['message' => 'Head Office created successfully', 'data' => $headOffice], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(HeadOffice $headOffice): JsonResponse
    {
        $headOffice->load(['customer', 'branches', 'callServers']);
        return response()->json($headOffice);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, HeadOffice $headOffice): JsonResponse
    {
        $validated = $request->validate([
            'customer_id' => 'sometimes|exists:customers,id',
            'name' => 'sometimes|string|max:100',
            'code' => 'nullable|string|max:20',
            'type' => 'sometimes|in:basic,ha,fo',
            'country' => 'nullable|string|max:50',
            'province' => 'nullable|string|max:50',
            'city' => 'nullable|string|max:50',
            'district' => 'nullable|string|max:50',
            'address' => 'nullable|string',
            'contact_name' => 'nullable|string|max:100',
            'contact_phone' => 'nullable|string|max:30',
            'description' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $headOffice->update($validated);

        return response()->json(['message' => 'Head Office updated successfully', 'data' => $headOffice]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(HeadOffice $headOffice): JsonResponse
    {
        $headOffice->delete();
        return response()->json(['message' => 'Head Office deleted successfully']);
    }
}
