<?php

namespace App\Http\Controllers\Api\V1\Organization;

use App\Http\Controllers\Controller;
use App\Models\SubBranch;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class SubBranchController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request): JsonResponse
    {
        $query = SubBranch::query()->with('branch');

        if ($request->has('search')) {
            $search = $request->search;
            $query->where('name', 'like', "%{$search}%")
                ->orWhere('code', 'like', "%{$search}%");
        }

        if ($request->has('branch_id')) {
            $query->where('branch_id', $request->branch_id);
        }

        $subBranches = $query->paginate($request->get('per_page', 15));

        return response()->json($subBranches);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'branch_id' => 'required|exists:branches,id',
            'name' => 'required|string|max:100',
            'code' => 'nullable|string|max:20',
            'address' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $subBranch = SubBranch::create($validated);

        return response()->json(['message' => 'Sub Branch created successfully', 'data' => $subBranch], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(SubBranch $subBranch): JsonResponse
    {
        $subBranch->load('branch');
        return response()->json($subBranch);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, SubBranch $subBranch): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'sometimes|string|max:100',
            'code' => 'nullable|string|max:20',
            'address' => 'nullable|string',
            'is_active' => 'boolean',
        ]);

        $subBranch->update($validated);

        return response()->json(['message' => 'Sub Branch updated successfully', 'data' => $subBranch]);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(SubBranch $subBranch): JsonResponse
    {
        $subBranch->delete();
        return response()->json(['message' => 'Sub Branch deleted successfully']);
    }
}
