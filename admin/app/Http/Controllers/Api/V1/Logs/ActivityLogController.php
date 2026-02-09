<?php

namespace App\Http\Controllers\Api\V1\Logs;

use App\Http\Controllers\Controller;
use App\Models\ActivityLog;
use Illuminate\Http\JsonResponse;

class ActivityLogController extends Controller
{
    public function index(): JsonResponse
    {
        $logs = ActivityLog::with('user')->orderBy('created_at', 'desc')->get();

        return response()->json([
            'success' => true,
            'data' => $logs
        ]);
    }

    public function show(string $id): JsonResponse
    {
        $log = ActivityLog::with('user')->findOrFail($id);

        return response()->json([
            'success' => true,
            'data' => $log
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        $log = ActivityLog::findOrFail($id);
        $log->delete();

        return response()->json([
            'success' => true,
            'message' => 'Activity log deleted successfully'
        ]);
    }
}
