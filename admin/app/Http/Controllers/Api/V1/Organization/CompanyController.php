<?php

namespace App\Http\Controllers\Api\V1\Organization;

use App\Http\Controllers\Controller;
use App\Models\Customer;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class CompanyController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = Customer::query()->withCount(['headOffices', 'branches']);

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('name', 'like', "%{$search}%")
                ->orWhere('code', 'like', "%{$search}%");
        }

        $companies = $query->paginate($request->get('per_page', 15));

        return response()->json($companies);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:100',
            'code' => 'nullable|string|max:20',
            'contact_person' => 'nullable|string|max:100',
            'email' => 'nullable|email',
            'phone' => 'nullable|string|max:30',
            'address' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $company = Customer::create($validated);

        return response()->json(['message' => 'Company created successfully', 'data' => $company], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(Customer $company): JsonResponse
    {
        $company->load(['headOffices', 'branches']);
        return response()->json($company);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Customer $company): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'sometimes|string|max:100',
            'code' => 'nullable|string|max:20',
            'contact_person' => 'nullable|string|max:100',
            'email' => 'nullable|email',
            'phone' => 'nullable|string|max:30',
            'address' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $company->update($validated);

        return response()->json(['message' => 'Company updated successfully', 'data' => $company]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Customer $company): JsonResponse
    {
        $company->delete();
        return response()->json(['message' => 'Company deleted successfully']);
    }
}
